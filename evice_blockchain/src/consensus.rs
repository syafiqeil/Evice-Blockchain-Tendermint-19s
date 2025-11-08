// src/consensus.rs

use borsh::{BorshSerialize, BorshDeserialize};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use crate::{Address, Signature};
use crate::blockchain::Block;
use crate::crypto::{SIGNATURE_SIZE, KeyPair};

// Pesan utama yang akan dikirim melalui jaringan P2P untuk konsensus
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum ConsensusMessage {
    Propose(Block),
    Prevote(Vote),
    Precommit(Vote),
    /// Menyebarkan hash dari proposal blok baru
    ProposeHash(Vec<u8>),
    /// Meminta proposal blok lengkap berdasarkan hash-nya
    GetProposal(Vec<u8>),
}

// Struct untuk pesan suara (digunakan untuk Prevote dan Precommit)
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct Vote {
    pub block_hash: Vec<u8>,
    pub height: u64,
    pub round: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Signature,
    pub voter_address: Address,
    pub mempool_hash: Vec<u8>,
}

impl Vote {
    pub fn new(block_hash: Vec<u8>, height: u64, round: u64, voter_address: Address, mempool_hash: Vec<u8>) -> Self {
        Self {
            block_hash,
            height,
            round,
            signature: [0; SIGNATURE_SIZE], 
            voter_address,
            mempool_hash,
        }
    }
    // Membuat hash dari konten vote yang akan ditandatangani
    pub fn message_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.height.to_be_bytes());
        hasher.update(&self.round.to_be_bytes());
        hasher.update(&self.block_hash);
        hasher.update(&self.mempool_hash);
        hasher.finalize().to_vec()
    }

    // Menandatangani vote dan mengembalikan vote yang sudah ditandatangani
    pub fn sign(mut self, keypair: &KeyPair) -> Self {
        let hash = self.message_hash();
        self.signature = keypair.sign(&hash);
        self
    }
}