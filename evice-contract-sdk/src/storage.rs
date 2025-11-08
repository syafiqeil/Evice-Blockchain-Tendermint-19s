// evice-contract-sdk/src/storage.rs

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
// Ganti RwLock dari spin dengan Once untuk inisialisasi aman
use spin::{Once, RwLock};

/// Struktur penyimpanan berbasis memori (sederhana, untuk kontrak smart contract)
#[derive(Default)] // Tambahkan Default untuk inisialisasi yang lebih mudah
pub struct Storage {
    pub data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Storage {
    pub fn new() -> Self {
        Storage { data: BTreeMap::new() }
    }

    // Fungsi-fungsi ini tidak lagi digunakan secara langsung, tapi kita biarkan jika diperlukan di masa depan.
    pub fn insert<T: BorshSerialize>(&mut self, key: Vec<u8>, value: &T) {
        if let Ok(encoded_data) = borsh::to_vec(value) {
            self.data.insert(key, encoded_data);
        }
    }

    pub fn get<T: BorshDeserialize>(&self, key: &[u8]) -> Option<T> {
        self.data
            .get(key)
            .and_then(|encoded| T::try_from_slice(encoded).ok())
    }
}

// ---------------------------------------------------------------------
// PENGGANTI GLOBAL_STORAGE YANG AMAN (SAFE)
// ---------------------------------------------------------------------

// Gunakan `spin::Once` untuk memastikan inisialisasi hanya terjadi sekali dan aman.
// Tidak ada lagi `static mut` dan `unsafe`.
static GLOBAL_STORAGE: Once<Arc<RwLock<Storage>>> = Once::new();

/// Helper function untuk mendapatkan akses ke storage global.
/// Fungsi ini akan menginisialisasi storage pada panggilan pertama dan mengembalikannya
/// pada semua panggilan berikutnya.
fn get_storage() -> &'static Arc<RwLock<Storage>> {
    GLOBAL_STORAGE.call_once(|| Arc::new(RwLock::new(Storage::new())))
}

/// Simpan data ke storage global.
pub fn write<T: BorshSerialize>(key: &[u8], value: &T) {
    let encoded = borsh::to_vec(value).expect("borsh encode failed");
    // Dapatkan akses ke storage dan langsung tulis (write lock).
    get_storage().write().data.insert(key.to_vec(), encoded);
}

/// Ambil data dari storage global.
pub fn read<T: BorshDeserialize>(key: &[u8]) -> Option<T> {
    // Dapatkan akses ke storage, dapatkan read lock, lalu coba baca datanya.
    get_storage()
        .read()
        .data
        .get(key)
        .and_then(|encoded| T::try_from_slice(encoded).ok())
}
