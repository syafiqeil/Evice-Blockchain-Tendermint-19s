// src/mempool.rs

use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::time::{Instant, Duration};
use sha2::{Sha256, Digest};
use log::{debug, warn, info};

use crate::{Transaction, TransactionData};
use crate::blockchain::Blockchain;
use crate::state::StateMachine;
use crate::crypto;

pub struct Mempool {
    transactions: Arc<Mutex<Vec<Transaction>>>,
    tx_hashes: Arc<Mutex<HashSet<Vec<u8>>>>,
    peer_tx_counts: Arc<Mutex<HashMap<String, usize>>>,
    peer_last_seen: Arc<Mutex<HashMap<String, Instant>>>,
}


impl Clone for Mempool {
    fn clone(&self) -> Self {
        Self {
            transactions: Arc::new(Mutex::new(Vec::new())),
            tx_hashes: Arc::new(Mutex::new(HashSet::new())),
            peer_tx_counts: Arc::new(Mutex::new(HashMap::new())),
            peer_last_seen: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions: Arc::new(Mutex::new(Vec::new())),
            tx_hashes: Arc::new(Mutex::new(HashSet::new())),
            peer_tx_counts: Arc::new(Mutex::new(HashMap::new())),
            peer_last_seen: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_transaction(
        &self,
        tx: Transaction,
        peer_id: &str,
        state: &StateMachine,
        blockchain: &Blockchain
    ) -> Result<(), &'static str> {
        // 1. Dapatkan akun pengirim dari state untuk mendapatkan kunci publik penuh.
        let sender_account = state
            .get_account(&tx.sender)
            .map_err(|_| "Gagal akses database untuk verifikasi")?
            .ok_or("Akun pengirim tidak ditemukan untuk verifikasi")?;

        // 2. Lakukan verifikasi menggunakan kunci publik PENUH dari akun.
        if !crypto::verify(
            &sender_account.signing_public_key, // <-- Kunci publik 1312-byte yang benar
            &tx.message_hash(),
            &tx.signature
        ) {
            warn!("MEMPOOL: Ditolak, tanda tangan tidak valid.");
            return Err("Tanda tangan tidak valid");
        }

        if tx.nonce < sender_account.nonce {
            warn!(
                "MEMPOOL: Ditolak (peer: {}), nonce usang (expected >= {}, got {}).",
                peer_id, sender_account.nonce, tx.nonce
            );
            return Err("Nonce sudah usang (replay attack?)");
        }

        // Dapatkan base_fee dari blok terakhir untuk estimasi biaya.
        let last_header = blockchain.chain.last().map(|b| &b.header);
        let base_fee_per_gas = last_header.map_or(
            crate::blockchain::INITIAL_BASE_FEE, 
            |h| blockchain.calculate_next_base_fee(h)
        );

        let tip = tx.max_priority_fee_per_gas.min(tx.max_fee_per_gas.saturating_sub(base_fee_per_gas));
        let fee_paid = (base_fee_per_gas + tip) * tx.data.base_gas_cost();
        let main_tx_amount = match &tx.data {
            TransactionData::Transfer { amount, .. } |
            TransactionData::Stake { amount, .. } |
            TransactionData::DepositToL2 { amount, .. } => *amount,
            _ => 0,
        };
        let total_deduction = main_tx_amount + fee_paid;

        if sender_account.balance < total_deduction {
            warn!(
                "MEMPOOL: Ditolak, saldo tidak cukup (memiliki {}, butuh {}).",
                sender_account.balance, total_deduction
            );
            return Err("Saldo tidak cukup");
        }

        // 2) Per-peer rate simple enforcement
        const MIN_PEER_INTERVAL_MS: u128 = 50; // minimal interval per peer
        const MAX_TX_PER_PEER: usize = 100;
        const MAX_MEMPOOL_SIZE: usize = 5000;

        {
            let mut last_seen = self.peer_last_seen.lock().unwrap();
            let now = std::time::Instant::now();
            if let Some(prev) = last_seen.get(peer_id) {
                if now.duration_since(*prev) < Duration::from_millis(MIN_PEER_INTERVAL_MS as u64) { // <-- Gunakan konstanta
                    return Err("Terlalu banyak transaksi dari peer yang sama dalam waktu singkat");
                }
            }
            last_seen.insert(peer_id.to_string(), now);
        }

        {
            let mut counts = match self.peer_tx_counts.lock() {
                Ok(g) => g,
                Err(_) => return Err("peer_tx_counts poisoned"),
            };
            let c = counts.entry(peer_id.to_string()).or_insert(0);
            if *c >= MAX_TX_PER_PEER {
                return Err("Peer mempool limit reached");
            }
            *c += 1;
        }

        // 3) Global mempool cap & eviction by fee if necessary
        let mut txs = match self.transactions.lock() {
            Ok(g) => g,
            Err(_) => return Err("Mempool mutex poisoned"),
        };

        if txs.len() >= MAX_MEMPOOL_SIZE {
            // evict lowest fee tx (linear scan; optimize later)
            if let Some((idx, _)) = txs.iter().enumerate().min_by_key(|(_, t)| {
                // priority key: max_fee_per_gas then max_priority_fee_per_gas
                (t.max_fee_per_gas, t.max_priority_fee_per_gas)
            }) {
                txs.remove(idx);
            } else {
                return Err("Mempool full");
            }
        }

        // 4) Basic checks (nonce, balance) should be done by caller when adding with blockchain snapshot
        txs.push(tx);
        Ok(())
    }

    /// Mengambil transaksi berprioritas tertinggi dan MENGHAPUSNYA dari pool.
    pub fn get_transactions(&self, count: usize) -> Vec<Transaction> {
        let mut pool = self.transactions.lock().unwrap();
        let mut hashes = self.tx_hashes.lock().unwrap();

        // Menggunakan logika pengurutan yang sama persis dengan `peek_transactions`.
        pool.sort_by(|a, b| {
            b.max_priority_fee_per_gas.cmp(&a.max_priority_fee_per_gas)
            .then_with(|| a.nonce.cmp(&b.nonce))
            .then_with(|| a.message_hash().cmp(&b.message_hash()))
        });
        
        let at_most = std::cmp::min(count, pool.len());

        // Menggunakan `drain` untuk mengambil elemen dari depan secara efisien.
        let to_return: Vec<Transaction> = pool.drain(..at_most).collect();
        
        // Hapus hash dari transaksi yang diambil
        for tx in &to_return {
            hashes.remove(&tx.message_hash());
        }
        
        if !to_return.is_empty() {
            debug!("MEMPOOL: Mengambil {} transaksi untuk blok baru.", to_return.len());
        }
        to_return
    }

    /// Menghapus satu transaksi spesifik dari mempool, misalnya setelah terbukti tidak valid.
    pub fn remove_single_transaction(&self, tx_to_remove: &Transaction) {
        let tx_hash = tx_to_remove.message_hash();
        info!("MEMPOOL: Menghapus transaksi beracun/tidak valid: {}", hex::encode(&tx_hash));
        let mut pool = self.transactions.lock().unwrap();
        let mut hashes = self.tx_hashes.lock().unwrap();
        
        pool.retain(|tx| tx.message_hash() != tx_hash);
        hashes.remove(&tx_hash);
    }

    pub fn add_from_p2p(
        &self,
        tx: Transaction,
        state: &StateMachine, // Tambahkan state sebagai argumen
    ) -> Result<(), &'static str> {
        // 1. Dapatkan akun pengirim dari state untuk mendapatkan kunci publik penuh.
        let sender_account = state
            .get_account(&tx.sender)
            .map_err(|_| "Gagal akses database saat verifikasi P2P")?
            .ok_or("Akun pengirim tidak ditemukan saat verifikasi P2P")?;

        // 2. Lakukan verifikasi menggunakan kunci publik PENUH dari akun.
        if !crypto::verify(
            &sender_account.signing_public_key,
            &tx.message_hash(),
            &tx.signature,
        ) {
            warn!("MEMPOOL: Transaksi dari P2P ditolak, tanda tangan tidak valid.");
            return Err("Tanda tangan tidak valid");
        }

        // 3. Lakukan pemeriksaan duplikat (logika ini sudah benar)
        let tx_hash = tx.message_hash();
        let mut hashes = self.tx_hashes.lock().unwrap();
        if hashes.contains(&tx_hash) {
            return Err("Transaksi duplikat");
        }

        // 4. Tambahkan ke pool jika semua validasi lolos
        let mut pool = self.transactions.lock().unwrap();
        pool.push(tx);
        hashes.insert(tx_hash);

        debug!(
            "MEMPOOL: Transaksi dari P2P ditambahkan. Total di mempool: {}",
            pool.len()
        );
        Ok(())
    }

    pub fn remove_transactions(&self, transactions_to_remove: &[Transaction]) {
        if transactions_to_remove.is_empty() {
            return;
        }
        let mut pool = self.transactions.lock().unwrap();
        let mut hashes = self.tx_hashes.lock().unwrap();
        
        let remove_hashes: HashSet<Vec<u8>> = transactions_to_remove.iter().map(|tx| tx.message_hash()).collect();
        
        // --- `retain` adalah cara efisien untuk menghapus dari heap ---
        pool.retain(|tx| !remove_hashes.contains(&tx.message_hash()));
        for hash in remove_hashes {
            hashes.remove(&hash);
        }

        debug!(
            "MEMPOOL: {} transaksi yang terkonfirmasi telah dihapus. Sisa: {}",
            transactions_to_remove.len(),
            pool.len()
        );
    }

    pub fn revalidate_against_new_state(&self, state: &StateMachine) {
        let mut pool = self.transactions.lock().unwrap();
        let mut hashes = self.tx_hashes.lock().unwrap();
        
        let initial_count = pool.len();
        
        // `retain` adalah cara efisien untuk menghapus elemen berdasarkan kondisi
        pool.retain(|tx| {
            if let Ok(Some(account)) = state.get_account(&tx.sender) {
                // Simpan transaksi HANYA jika nonce-nya masih valid
                if tx.nonce >= account.nonce {
                    return true; // Pertahankan
                }
            }
            // Jika akun tidak ada atau nonce sudah basi, hapus
            warn!("MEMPOOL (Re-validation): Menghapus transaksi basi dari {} (nonce: {})", hex::encode(tx.sender.as_ref()), tx.nonce);
            hashes.remove(&tx.message_hash());
            false // Hapus
        });
        
        let final_count = pool.len();
        if initial_count > final_count {
            info!("MEMPOOL (Re-validation): {} transaksi basi berhasil dibersihkan.", initial_count - final_count);
        }
    }

    // Mengambil satu transaksi berdasarkan hash
    pub fn get_transaction_by_hash(&self, hash_to_find: &[u8]) -> Option<Transaction> {
        let pool = self.transactions.lock().unwrap();
        pool.iter()
            .find(|tx| tx.message_hash() == hash_to_find)
            .cloned()
    }
    /// Mengembalikan daftar hash dari semua transaksi di mempool.
    pub fn get_all_hashes(&self) -> Vec<Vec<u8>> {
        let hashes = self.tx_hashes.lock().unwrap();
        hashes.iter().cloned().collect()
    }

    /// Mengambil transaksi lengkap dari mempool berdasarkan daftar hash.
    pub fn get_transactions_by_hashes(&self, hashes: &[Vec<u8>]) -> Vec<Transaction> {
        let pool = self.transactions.lock().unwrap();
        let hash_set: HashSet<_> = hashes.iter().collect();
        pool.iter()
            .filter(|tx| hash_set.contains(&tx.message_hash()))
            .cloned()
            .collect()
    }
    
    /// Menghitung satu hash yang merepresentasikan state mempool saat ini.
    /// Dilakukan dengan mengurutkan semua hash transaksi lalu menghash hasilnya.
    pub fn calculate_mempool_hash(&self) -> Vec<u8> {
        let mut hashes = self.get_all_hashes();
        if hashes.is_empty() {
            return vec![0; 32]; // Hash default untuk mempool kosong
        }

        // Urutkan secara deterministik
        hashes.sort();
        
        // Gabungkan semua hash menjadi satu byte array
        let combined: Vec<u8> = hashes.into_iter().flatten().collect();
        
        // Hash hasil gabungan
        Sha256::digest(&combined).to_vec()
    }

    /// Membersihkan semua transaksi dari mempool.
    /// Digunakan untuk pulih dari kondisi divergensi state.
    pub fn clear(&self) {
        let mut pool = self.transactions.lock().unwrap();
        let mut hashes = self.tx_hashes.lock().unwrap();
        if !pool.is_empty() {
            warn!("MEMPOOL: Membersihkan {} transaksi dari mempool untuk mengatasi divergensi.", pool.len());
            pool.clear();
            hashes.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, SIGNATURE_SIZE, ValidatorKeys};
    use crate::state::{Account, StateMachine};
    use crate::{Address, TransactionData};
    use tempfile::tempdir;

    // Helper function yang sudah diperbarui
    fn create_test_tx(sender_key: &KeyPair, recipient: Address, amount: u64, nonce: u64, fee: u64) -> Transaction {
        let data = TransactionData::Transfer { recipient, amount };
        let mut tx = Transaction {
            sender: Address(sender_key.public_key_bytes()),
            data,
            fee,
            nonce,
            signature: [0; SIGNATURE_SIZE],
        };
        let hash = tx.message_hash();
        tx.signature = sender_key.sign(&hash);
        tx
    }

    #[test]
    fn test_add_valid_transaction() {
        let dir = tempdir().unwrap();
        let state = StateMachine::new(dir.path().to_str().unwrap()).unwrap();
        let mempool = Mempool::new();
        
        let user1_keys = KeyPair::new();
        let user1_address = Address(user1_keys.public_key_bytes());
        let user2_address = Address(KeyPair::new().public_key_bytes());
        
        let user1_account = Account { balance: 1000, nonce: 0, staked_amount: 0, vrf_public_key: [0u8; 32] };
        state.db.put(user1_address.as_ref(), bincode::serialize(&user1_account).unwrap()).unwrap();
        
        let tx = create_test_tx(&user1_keys, user2_address, 100, 0, 10);

        let result = mempool.add_transaction(tx.clone(), &state);
        assert!(result.is_ok());
        assert_eq!(mempool.transactions.lock().unwrap().len(), 1);
    }
}