// src/lib.rs

use borsh::{BorshSerialize, BorshDeserialize};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use std::cmp::Ordering;
use std::convert::AsRef;
use sha2::Digest;
use keccak_hasher::KeccakHasher;
use trie_db::TrieLayout;

use crate::blockchain::{DoubleSignEvidence, Signature};
use crate::crypto::KeyPair;
use crate::governance::{Proposal, ProposalId};

pub use evice_core::{Address, WithdrawalProof, Leaf, MerkleTreeConfig};
pub mod blockchain;
pub mod crypto;
pub mod mempool;
pub mod p2p;
pub mod rpc;
pub mod state;
pub mod consensus;
pub mod governance;
pub mod l2_circuit;
pub mod keystore;
pub mod snapshot;
pub mod rpc_client;
pub mod serde_helpers;
pub mod genesis;
pub mod wasm_runtime;
pub mod trie_codec;

#[derive(Debug)]
pub struct EviceTrieLayout;
impl TrieLayout for EviceTrieLayout {
    type Hash = KeccakHasher;
    type Codec = crate::trie_codec::ProductionNodeCodec<KeccakHasher>;
    const USE_EXTENSION: bool = false;
    const ALLOW_EMPTY: bool = true;
    const MAX_INLINE_VALUE: Option<u32> = Some(32);
}

// ===================================================================
//            STRUKTUR DATA BARU UNTUK KONSENSUS BFT
// ===================================================================

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum VoteType {
    Prevote,
    Precommit,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vote {
    pub block_hash: Vec<u8>,
    pub block_index: u64,
    pub vote_type: VoteType,
    pub voter: Address,
    #[serde(with = "serde_bytes")]
    pub signature: Signature,
}

impl Vote {
    /// Membuat hash dari pesan vote yang akan ditandatangani.
    pub fn message_hash(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.block_hash);
        data.extend_from_slice(&self.block_index.to_be_bytes());
        data.extend_from_slice(&bincode::serialize(&self.vote_type).unwrap());
        data.extend_from_slice(self.voter.as_ref());
        
        let mut hasher = sha2::Sha256::new();
        hasher.update(&data);
        hasher.finalize().to_vec()
    }

    /// Menandatangani vote menggunakan keypair validator.
    pub fn sign(mut self, keypair: &KeyPair) -> Self {
        let hash = self.message_hash();
        self.signature = keypair.sign(&hash);
        self
    }
}

pub type VrfPublicKeyBytes = [u8; 32];

#[serde_as]
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransactionData {
    Transfer {
        recipient: Address,
        amount: u64,
    },
    Stake {
        amount: u64,
    },
    ReportDoubleSigning {
        evidence: DoubleSignEvidence,
    },
    /// Mengajukan proposal baru untuk pemungutan suara.
    SubmitProposal {
        proposal: Proposal,
    },
    /// Memberikan suara pada proposal yang ada.
    CastVote {
        proposal_id: ProposalId,
        vote: bool, // true untuk 'Ya', false untuk 'Tidak'
    },
    SubmitRollupBatch {
        /// Hash dari state L2 sebelumnya, untuk memastikan kontinuitas.
        #[serde(with = "serde_bytes")]
        old_state_root: Vec<u8>,
        /// Hash dari state L2 yang baru setelah batch dieksekusi.
        #[serde(with = "serde_bytes")]
        new_state_root: Vec<u8>,
        /// Data transaksi L2 yang dikompresi (untuk Data Availability).
        #[serde(with = "serde_bytes")]
        compressed_batch: Vec<u8>,
        /// Bukti kriptografis bahwa transisi dari old_state_root ke new_state_root adalah valid.
        #[serde(with = "serde_bytes")]
        zk_proof: Vec<u8>,
        #[serde(default)] // Akan default ke `false` saat deserialisasi jika tidak ada
        is_test_tx: bool,
        // Bukti kepemimpinan sequencer
        #[serde(with = "serde_bytes")]
        vrf_output: Vec<u8>,
        #[serde(with = "serde_bytes")]
        vrf_proof: Vec<u8>,
        // Tanda tangan dari anggota DAC yang mengonfirmasi ketersediaan data.
        #[serde_as(as = "Vec<Bytes>")]
        dac_signatures: Vec<Signature>,
    },
    /// Mengunci token di L1 untuk dicetak di L2.
    DepositToL2 {
        amount: u64,
    },
    UpdateVrfKey {
        #[serde(with = "serde_bytes")]
        new_vrf_public_key: VrfPublicKeyBytes,
    },
    // Transaksi untuk manajemen sequencer
    RegisterAsSequencer,
    DeregisterAsSequencer,
    /// Menyebarkan kode smart contract WASM ke blockchain.
    DeployContract {
        #[serde(with = "serde_bytes")]
        code: Vec<u8>,
    },
    /// Memanggil fungsi pada smart contract yang sudah ada.
    CallContract {
        contract_address: Address,
        #[serde(with = "serde_bytes")]
        call_data: Vec<u8>, // Input yang dienkode untuk fungsi kontrak
    },
    /// Menarik dana dari kas (treasury) yang memerlukan persetujuan M-of-N dari komite dev.
    WithdrawFromTreasury {
        recipient: Address,
        amount: u64,
        #[serde_as(as = "Vec<Bytes>")]
        approvals: Vec<Signature>,
    },
}

impl TransactionData {
    /// Mengembalikan biaya gas dasar untuk setiap jenis transaksi.
    pub fn base_gas_cost(&self) -> u64 {
        const BASE_TX_GAS: u64 = 21_000;
        match self {
            TransactionData::Transfer {..} => BASE_TX_GAS,
            TransactionData::Stake {..} => BASE_TX_GAS + 5_000,
            TransactionData::SubmitProposal { proposal } => {
                // Biaya proposal tergantung pada ukuran deskripsi untuk mencegah spam
                BASE_TX_GAS + 10_000 + (proposal.description.len() as u64 * 10)
            },
            TransactionData::CastVote {..} => BASE_TX_GAS + 2_000,
            TransactionData::ReportDoubleSigning {..} => BASE_TX_GAS + 15_000,
            TransactionData::DepositToL2 {..} => BASE_TX_GAS + 20_000,
            // Verifikasi ZK-Proof adalah operasi yang paling mahal secara komputasi
            TransactionData::SubmitRollupBatch { compressed_batch, .. } => {
                BASE_TX_GAS + 300_000 + (compressed_batch.len() as u64 * 50)
            },
            TransactionData::DeployContract { code } => {
            // Biaya deploy tergantung pada ukuran kode untuk mencegah spam
            BASE_TX_GAS + 150_000 + (code.len() as u64 * 200)
            },
            TransactionData::CallContract { .. } => {
                // Biaya dasar untuk pemanggilan, biaya eksekusi aktual akan dihitung nanti
                BASE_TX_GAS + 5_000 
            },
            TransactionData::UpdateVrfKey {..} => BASE_TX_GAS + 7_000,
            TransactionData::RegisterAsSequencer | TransactionData::DeregisterAsSequencer => BASE_TX_GAS + 10_000,
            TransactionData::WithdrawFromTreasury { approvals, .. } => {
                BASE_TX_GAS + 25_000 + (approvals.len() as u64 * 5_000)
            },
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, Eq)]
pub struct Transaction {
    pub sender: Address,
    pub data: TransactionData,
    pub nonce: u64,  
    /// Biaya maksimum per unit gas yang bersedia dibayar pengguna.
    /// Termasuk base_fee + priority_fee.
    pub max_fee_per_gas: u64,
    /// Tip maksimum yang bersedia dibayar pengguna kepada validator.
    pub max_priority_fee_per_gas: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Signature,
}

// --- Implementasi manual untuk perbandingan dan ordering ---
impl PartialEq for Transaction {
    // Kita hanya peduli pada hash untuk kesetaraan, karena itu unik.
    fn eq(&self, other: &Self) -> bool {
        self.message_hash() == other.message_hash()
    }
}

impl Ord for Transaction {
    // BinaryHeap adalah max-heap, jadi kita ingin 'Greater' berarti prioritas lebih tinggi.
    fn cmp(&self, other: &Self) -> Ordering {
        // Untuk perbandingan, kita asumsikan sebuah base_fee sementara.
        // Di dunia nyata, proposer akan menggunakan base_fee dari blok parent.
        // Di sini kita bisa gunakan nilai konstan atau default.
        const FAKE_BASE_FEE: u64 = 10; 

        // Tip efektif adalah prioritas yang bersedia dibayar di atas base_fee.
        let self_effective_tip = self.max_fee_per_gas.saturating_sub(FAKE_BASE_FEE)
            .min(self.max_priority_fee_per_gas);
        
        let other_effective_tip = other.max_fee_per_gas.saturating_sub(FAKE_BASE_FEE)
            .min(other.max_priority_fee_per_gas);

        // 1. Prioritas utama: Tip efektif (lebih tinggi lebih baik)
        self_effective_tip.cmp(&other_effective_tip)
            // 2. Tie-breaker: nonce (lebih rendah lebih baik, jadi kita balik urutannya)
            .then_with(|| other.nonce.cmp(&self.nonce))
    }
}

impl PartialOrd for Transaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Implementasi Hash secara manual agar konsisten dengan PartialEq
impl std::hash::Hash for Transaction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.message_hash().hash(state);
    }
}