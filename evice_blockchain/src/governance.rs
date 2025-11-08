// src/governance.rs

use borsh::{BorshSerialize, BorshDeserialize};
use serde::{Deserialize, Serialize};
use crate::Address;

// Tipe data untuk identifikasi unik proposal.
pub type ProposalId = u64;

/// Merepresentasikan proposal yang diajukan oleh komunitas.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Proposal {
    /// Deskripsi singkat mengenai tujuan proposal.
    pub title: String,
    /// Penjelasan mendalam mengenai proposal, termasuk alasan dan dampaknya.
    pub description: String,
    /// Jenis perubahan yang diusulkan.
    pub action: ProposalAction,
}

/// Mendefinisikan tindakan spesifik yang akan dieksekusi jika proposal disetujui.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProposalAction {
    /// Mengubah parameter jaringan, misal: nilai MINIMUM_STAKE.
    UpdateParameter { key: String, value: String },
    /// Proposal teks biasa untuk sinyal komunitas (tidak ada eksekusi on-chain).
    Text,
    // --- Aksi untuk upgrade runtime ---
    UpgradeRuntime {
        /// Hash (misal, SHA256) dari binary node yang baru.
        binary_hash: Vec<u8>,
        /// URL atau IPFS CID dari mana binary bisa diunduh.
        download_url: String,
        /// Nomor blok di mana upgrade akan diaktifkan.
        activation_block_height: u64,
    }
}

/// Menyimpan status dan metadata dari sebuah proposal yang ada di state.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProposalState {
    pub id: ProposalId,
    pub proposal: Proposal,
    /// Alamat yang mengajukan proposal.
    pub proposer: Address,
    /// Nomor blok saat proposal diajukan.
    pub start_block: u64,
    /// Nomor blok saat periode voting berakhir.
    pub end_block: u64,
    /// Jumlah suara 'Ya'. Bobot suara bisa berdasarkan jumlah stake.
    pub yes_votes: u64,
    /// Jumlah suara 'Tidak'.
    pub no_votes: u64,
    /// Apakah proposal sudah dieksekusi.
    pub executed: bool,
    /// Daftar alamat yang sudah memberikan suara untuk mencegah double-voting.
    pub voters: std::collections::HashSet<Address>,
}
