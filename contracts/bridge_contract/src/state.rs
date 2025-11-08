// contracts/bridge_contract/src/state.rs

use borsh::{BorshDeserialize, BorshSerialize};
use evice_core::{Address, WithdrawalProof};
use alloc::vec::Vec;

// State yang disimpan di storage kontrak
#[derive(BorshSerialize, BorshDeserialize, Debug, Default)]
pub struct BridgeState {
    pub daily_limit: u64,
    pub last_withdrawal_day: u64,
    pub withdrawn_today: u64,
    pub owner: Address, // Alamat yang bisa mengubah limit
    pub processed_l2_roots: Vec<Vec<u8>>,
}

// Aksi yang bisa dipanggil
#[derive(BorshDeserialize)]
pub enum CallAction {
    // Inisialisasi state awal (hanya bisa dipanggil sekali)
    Initialize { daily_limit: u64, owner: Address },
    // Fungsi penarikan dana
    Withdraw { amount: u64, proof: WithdrawalProof },
    // Fungsi untuk mengubah limit (hanya oleh owner)
    SetDailyLimit { new_limit: u64 },
}

// Kunci untuk menyimpan state utama di storage
pub const STATE_KEY: &[u8] = b"STATE";