// src/snapshot.rs

use ark_serialize::Read;
use borsh::{BorshSerialize, BorshDeserialize};
use parity_db::Db;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tempfile::NamedTempFile;
use serde::{Deserialize, Serialize};
use log::{info, error};

use crate::state::{COL_TRIE, StateError, TrieRoot, ColumnId};

pub const SNAPSHOT_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB per chunk

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct SnapshotMetadata {
    pub height: u64,
    pub state_root: TrieRoot,
    pub total_chunks: u32,
    pub file_name: String,
}

/// Membuat snapshot dari state trie saat ini.
pub fn create_snapshot<P: AsRef<Path>>(db: Arc<Db>, height: u64, state_root: TrieRoot, snapshot_dir: P) -> Result<SnapshotMetadata, StateError> {
    let snapshot_file_name = format!("snapshot_h{}_r{}.db.zstd", height, hex::encode(&state_root[..4]));
    let snapshot_path = snapshot_dir.as_ref().join(&snapshot_file_name);
    let temp_path = snapshot_dir.as_ref().join("snapshot.tmp");

    info!("Memulai pembuatan snapshot ke: {:?}", snapshot_path);

    let mut temp_file = OpenOptions::new().write(true).create(true).truncate(true).open(&temp_path)?;
    let mut iter = db.iter(COL_TRIE)?;
    
    while let Ok(Some((key, value))) = iter.next() {
        temp_file.write_all(&(key.len() as u32).to_be_bytes())?;
        temp_file.write_all(&key)?;
        temp_file.write_all(&(value.len() as u32).to_be_bytes())?;
        temp_file.write_all(&value)?;
    }
    temp_file.sync_all()?;
    drop(temp_file);

    let mut temp_file_read = File::open(&temp_path)?;
    let snapshot_file = File::create(&snapshot_path)?;
    let mut encoder = zstd::stream::write::Encoder::new(snapshot_file, 3)?;
    std::io::copy(&mut temp_file_read, &mut encoder)?;
    encoder.finish()?;
    
    std::fs::remove_file(&temp_path)?;

    let file_size = std::fs::metadata(&snapshot_path)?.len();
    let total_chunks = (file_size as f64 / SNAPSHOT_CHUNK_SIZE as f64).ceil() as u32;

    let metadata = SnapshotMetadata {
        height,
        state_root,
        total_chunks,
        file_name: snapshot_file_name.clone(),
    };

    let metadata_path = snapshot_dir.as_ref().join("latest_snapshot.json");
    let metadata_file = File::create(metadata_path)?;
    serde_json::to_writer(metadata_file, &metadata).map_err(|e| {
        error!("Gagal menulis metadata snapshot: {}", e);
        StateError::SerializationError(bincode::Error::new(bincode::ErrorKind::Custom(e.to_string())))
    })?;

    info!("Snapshot berhasil dibuat: {}", snapshot_file_name);
    Ok(metadata)
}

/// Membaca sepotong (chunk) dari file snapshot yang ada.
pub fn read_snapshot_chunk<P: AsRef<Path>>(snapshot_dir: P, file_name: &str, chunk_index: u32) -> Result<Option<Vec<u8>>, std::io::Error> {
    let snapshot_path = snapshot_dir.as_ref().join(file_name);
    if !snapshot_path.exists() {
        return Ok(None);
    }

    let mut file = File::open(snapshot_path)?;
    let offset = chunk_index as u64 * SNAPSHOT_CHUNK_SIZE as u64;
    
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset))?;

    let mut buffer = vec![0; SNAPSHOT_CHUNK_SIZE];
    let bytes_read = file.read(&mut buffer)?;
    
    if bytes_read == 0 {
        return Ok(None);
    }
    
    buffer.truncate(bytes_read);
    Ok(Some(buffer))
}

/// Menemukan dan mem-parsing metadata snapshot terbaru dari direktori.
pub fn find_latest_snapshot<P: AsRef<Path>>(snapshot_dir: P) -> Result<Option<SnapshotMetadata>, std::io::Error> {
    let metadata_path = snapshot_dir.as_ref().join("latest_snapshot.json");
    if metadata_path.exists() {
        let file = File::open(metadata_path)?;
        serde_json::from_reader(file).map(Some).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    } else {
        Ok(None)
    }
}

/// Memuat state dari file snapshot, menimpa state trie yang ada.
pub fn load_snapshot<P: AsRef<Path>>(db: Arc<Db>, snapshot_dir: P, metadata: &SnapshotMetadata) -> Result<(), StateError> {
    let snapshot_path = snapshot_dir.as_ref().join(&metadata.file_name);
    let temp_path = snapshot_dir.as_ref().join("snapshot-load.tmp");

    info!("Memulai pemulihan dari snapshot: {:?}", snapshot_path);

    let snapshot_file = File::open(&snapshot_path)?;
    let mut decoder = zstd::stream::read::Decoder::new(snapshot_file)?;
    let mut temp_file = OpenOptions::new().write(true).create(true).truncate(true).open(&temp_path)?;
    std::io::copy(&mut decoder, &mut temp_file)?;
    temp_file.sync_all()?;
    drop(temp_file);

    info!("Membersihkan state trie yang lama...");
    let mut delete_ops: Vec<(ColumnId, Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    let mut iter = db.iter(COL_TRIE)?;
    while let Ok(Some((key, _))) = iter.next() {
        delete_ops.push((COL_TRIE, key, None));
    }
    if !delete_ops.is_empty() {
        db.commit(delete_ops)?;
    }

    info!("Memuat state baru dari snapshot...");
    let mut temp_file_read = File::open(&temp_path)?;
    let mut buffer_4_bytes = [0u8; 4];
    
    loop {
        let mut ops: Vec<(ColumnId, Vec<u8>, Option<Vec<u8>>)> = Vec::with_capacity(100_000);

        for _ in 0..100_000 {
            if temp_file_read.read_exact(&mut buffer_4_bytes).is_err() {
                break;
            }
            let key_len = u32::from_be_bytes(buffer_4_bytes) as usize;
            let mut key = vec![0; key_len];
            temp_file_read.read_exact(&mut key)?;

            if temp_file_read.read_exact(&mut buffer_4_bytes).is_err() {
                 break;
            }
            let value_len = u32::from_be_bytes(buffer_4_bytes) as usize;
            let mut value = vec![0; value_len];
            temp_file_read.read_exact(&mut value)?;

            ops.push((COL_TRIE, key, Some(value)));
        }

        if !ops.is_empty() {
            db.commit(ops)?;
        } else {
            break; 
        }
    }
    
    std::fs::remove_file(&temp_path)?;

    info!("Pemulihan snapshot selesai. State root baru akan divalidasi oleh node.");
    Ok(())
}

/// Menulis data snapshot ke file secara atomik.
/// 1. Menulis ke file temporer di direktori yang sama.
/// 2. Melakukan flush dan sync untuk memastikan data tertulis ke disk.
/// 3. Mengganti nama file temporer ke nama file tujuan secara atomik.
pub fn write_snapshot_atomic(snapshot_path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = snapshot_path.parent().unwrap_or_else(|| Path::new("."));
    // Buat file temporer yang akan dihapus otomatis jika terjadi error
    let mut tmpfile = NamedTempFile::new_in(dir)?;

    // Gunakan kompresi zstd untuk konsistensi dengan create_snapshot
    {
        let mut encoder = zstd::stream::write::Encoder::new(&mut tmpfile, 3)?;
        encoder.write_all(data)?;
        encoder.finish()?;
    }

    // Pastikan semua data dari buffer OS tertulis ke disk
    tmpfile.as_file().sync_all()?;

    // Operasi rename ini bersifat atomik pada sebagian besar sistem file modern
    tmpfile.persist(snapshot_path)?;

    Ok(())
}
