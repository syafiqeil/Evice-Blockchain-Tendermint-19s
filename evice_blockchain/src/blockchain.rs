// src/blockchain.rs

use borsh::{BorshSerialize, BorshDeserialize};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use std::fs::File;
use std::collections::{HashSet, HashMap};

use log::{error, info, warn};
use merlin::Transcript;
use wasmer::{
    MemoryAccessError, RuntimeError, ExportError, 
    InstantiationError, CompileError,
};
use schnorrkel::{vrf::{VRFPreOut, VRFProof}, PublicKey as VrfPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use trie_db::{TrieMut, TrieDBMut, TrieDBMutBuilder, TrieError};
use hash_db::{AsHashDB, Hasher};
use keccak_hasher::KeccakHasher;

use crate::state::{
    Account, StateMachine, ParityDbTrieBackend, MINIMUM_STAKE, COL_L2_BATCHES, DEVELOPER_COMMITTEE,
    PROPOSAL_VOTING_PERIOD, L2_BRIDGE_ADDRESS, COL_METADATA, COL_BLOCKS, TREASURY_ADDRESS, ACTIVE_SEQUENCERS_KEY,
    COL_GOVERNANCE, COL_STATE_JOURNAL, NEXT_PROPOSAL_ID_KEY, VALIDATORS_KEY, L2_STATE_ROOT_KEY, STATE_ROOT_KEY,
    COL_CONTRACT_STORAGE, COL_CONTRACT_CODE, COL_TRIE, DATA_AVAILABILITY_COMMITTEE,
};
use crate::{
    crypto::{ADDRESS_SIZE, KeyPair, SIGNATURE_SIZE, public_key_to_address},
    consensus::{ConsensusMessage, Vote},
    governance::ProposalState,
    crypto, Address, Transaction, TransactionData, 
    serde_helpers, wasm_runtime, EviceTrieLayout,
};

pub type PublicKey = [u8; ADDRESS_SIZE];
pub type Signature = [u8; SIGNATURE_SIZE];
pub const INITIAL_BASE_FEE: u64 = 10; // Base fee untuk genesis block
const INACTIVITY_THRESHOLD_BLOCKS: u64 = 1000; // Validator dipenjara jika tidak aktif selama 1000 blok.
const INACTIVITY_SLASH_PERCENT: u64 = 1; // Stake dipotong 1% karena tidak aktif.

impl Transaction {
    pub fn message_hash(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.sender.as_ref());
        data.extend_from_slice(&bincode::serialize(&self.data).unwrap());
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.max_fee_per_gas.to_be_bytes());
        data.extend_from_slice(&self.max_priority_fee_per_gas.to_be_bytes());

        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    pub index: u64,
    pub timestamp: u128,
    pub prev_hash: Vec<u8>,
    pub state_root: Vec<u8>,
    pub transactions_root: Vec<u8>,
    #[serde(with = "serde_helpers::option_vec_u8")]
    pub l2_transactions_hash: Option<Vec<u8>>,
    pub authority: Address,
    pub gas_used: u64,
    pub base_fee_per_gas: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Signature,
}

impl BlockHeader {
    /// Mengumpulkan semua data header yang perlu ditandatangani, kecuali tanda tangan itu sendiri.
    pub fn message_to_sign(&self) -> Vec<u8> {    
        let mut header_for_signing = self.clone();
        header_for_signing.signature = [0; SIGNATURE_SIZE];
        bincode::serialize(&header_for_signing).expect("Gagal serialize header untuk ditandatangani")
    }

    pub fn calculate_hash(&self) -> Vec<u8> {
        let bytes = bincode::serialize(self).expect("Gagal serialize header untuk hash");
        Sha256::digest(&bytes).to_vec()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct DoubleSignEvidence {
    pub header1: BlockHeader,
    pub header2: BlockHeader,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub round: u64,
    #[serde(with = "serde_bytes")]
    pub vrf_output: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub vrf_proof: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum ChainMessage {
    /// Transaksi lengkap (untuk RPC atau saat diminta)
    NewTransaction(Transaction),
    /// Hash dari transaksi baru (untuk gossip)
    NewTransactionHash(Vec<u8>),
    /// Pesan konsensus lengkap atau hash-nya
    NewConsensusMessage(ConsensusMessage),
    /// Meminta transaksi lengkap berdasarkan hash
    GetTransaction(Vec<u8>),
}

#[derive(Debug, Error)]
pub enum BlockchainError {
    #[error("Database error: {0}")]
    Db(#[from] parity_db::Error),
    #[error("State error: {0}")]
    State(#[from] crate::state::StateError),
    #[error("Serialization error: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),
    #[error("Trie error: {0}")]
    Trie(String),
    #[error("Genesis block not found. Chain is uninitialized.")]
    UninitializedChain,
    #[error("Invalid block index. Expected {expected}, got {got}.")]
    InvalidIndex { expected: u64, got: u64 },
    #[error("Previous block hash does not match.")]
    PreviousHashMismatch,
    #[error("Block signature is invalid.")]
    InvalidSignature,
    #[error("Block authority is not a registered validator.")]
    NotAValidator,
    #[error("VRF proof verification failed.")]
    VrfVerificationFailed,
    #[error("VRF output does not meet the required threshold.")]
    VrfThresholdNotMet,
    #[error("Transaction validation failed: {0}")]
    TransactionInvalid(String),
    #[error("Stale nonce for transaction. Expected >= {expected}, got {got}.")]
    StaleNonce { expected: u64, got: u64 },
    #[error("Insufficient balance for transaction. Has {has}, needs {needs}.")]
    InsufficientBalance { has: u64, needs: u64 },
    #[error("State root mismatch! Expected {expected}, Got: {got}")]
    StateRootMismatch { expected: String, got: String },
    #[error("Invalid double signing evidence: {0}")]
    InvalidDoubleSignEvidence(String),
    #[error("Vote signature is invalid.")]
    InvalidVoteSignature,
    #[error("ZK proof synthesis error: {0}")]
    SynthesisError(#[from] ark_relations::r1cs::SynthesisError),
    #[error("WASM runtime error: {0}")]
    WasmError(String),
    #[error("State machine logic error: {0}")]
    LogicError(String),
}

impl From<CompileError> for BlockchainError {
    fn from(e: CompileError) -> Self { BlockchainError::WasmError(e.to_string()) }
}
impl From<InstantiationError> for BlockchainError {
    fn from(e: InstantiationError) -> Self { BlockchainError::WasmError(e.to_string()) }
}
impl From<ExportError> for BlockchainError {
    fn from(e: ExportError) -> Self { BlockchainError::WasmError(e.to_string()) }
}
impl From<RuntimeError> for BlockchainError {
    fn from(e: RuntimeError) -> Self { BlockchainError::WasmError(e.to_string()) }
}
impl From<MemoryAccessError> for BlockchainError {
    fn from(e: MemoryAccessError) -> Self { BlockchainError::WasmError(e.to_string()) }
}

impl<L: std::fmt::Debug, E: std::fmt::Debug> From<Box<TrieError<L, E>>> for BlockchainError {
    fn from(err: Box<TrieError<L, E>>) -> Self {
        BlockchainError::Trie(format!("{:?}", err))
    }
}

impl Block {
    pub fn calculate_transactions_root(transactions: &[Transaction]) -> Vec<u8> {
        if transactions.is_empty() {
            return vec![0; 32];
        }
        let mut tx_hashes = Vec::new();
        for tx in transactions {
            tx_hashes.extend_from_slice(&tx.message_hash());
        }
        let mut merkle_hasher = Sha256::new();
        merkle_hasher.update(tx_hashes);
        merkle_hasher.finalize().to_vec()
    }
}

pub struct Blockchain {
    pub chain: Vec<Block>,
    pub state: StateMachine,
    pub l2_verifying_key: VerifyingKey<Bls12_381>,
    processed_evidence: HashSet<Vec<u8>>,
    block_hash_cache: HashMap<Vec<u8>, Block>,
}

impl Blockchain {
    pub fn new(db_path: &str, vk_path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let state = StateMachine::new(db_path)?;
        let mut chain = Vec::new();
        let mut block_hash_cache = HashMap::new();

        if let Ok(Some(genesis_block_bytes)) = state.db.get(COL_BLOCKS, &0u64.to_be_bytes()) {
            if let Ok(genesis_block) = bincode::deserialize::<Block>(&genesis_block_bytes) {
                // Isi cache saat startup
                block_hash_cache.insert(genesis_block.header.calculate_hash(), genesis_block.clone());
                chain.push(genesis_block);
            }
        }

        info!("Mencoba memuat L2 Verifying Key dari '{}'...", vk_path);
        let mut vk_file = File::open(vk_path)
            .map_err(|e| format!("KRITIS: Gagal membuka file verifying key '{}'. Error: {}", vk_path, e))?;
        
        let l2_verifying_key = VerifyingKey::deserialize_uncompressed(&mut vk_file)
            .map_err(|e| format!("KRITIS: Gagal deserialisasi verifying key. Error: {}", e))?;
        
        info!("✅ L2 Verifying Key berhasil dimuat.");

        Ok(Self { chain, state, l2_verifying_key, processed_evidence: HashSet::new(),  block_hash_cache})
    }

    // Metode untuk mengambil blok berdasarkan hash-nya
    pub fn get_block_by_hash(&self, hash: &[u8]) -> Option<&Block> {
        self.block_hash_cache.get(hash)
    }

    fn validate_double_sign_evidence(&mut self, evidence: &DoubleSignEvidence) -> Result<(), BlockchainError> {
        let h1 = &evidence.header1;
        let h2 = &evidence.header2;

        // 1. Otoritas harus sama
        if h1.authority != h2.authority {
            return Err(BlockchainError::InvalidDoubleSignEvidence("Otoritas header tidak cocok.".into()));
        }

        // 2. Index blok harus sama
        if h1.index != h2.index {
            return Err(BlockchainError::InvalidDoubleSignEvidence("Index blok tidak sama.".into()));
        }

        // 3. Header harus berbeda (jika sama, bukan double signing)
        if h1.calculate_hash() == h2.calculate_hash() {
            return Err(BlockchainError::InvalidDoubleSignEvidence("Header identik, bukan double signing.".into()));
        }
        
        // 4. Kedua tanda tangan harus valid dari otoritas yang sama
        if !crypto::verify(h1.authority.as_ref(), &h1.calculate_hash(), &h1.signature) {
            return Err(BlockchainError::InvalidDoubleSignEvidence("Tanda tangan pada header 1 tidak valid.".into()));
        }
        if !crypto::verify(h2.authority.as_ref(), &h2.calculate_hash(), &h2.signature) {
            return Err(BlockchainError::InvalidDoubleSignEvidence("Tanda tangan pada header 2 tidak valid.".into()));
        }

        // 5. Otoritas harus merupakan validator yang terdaftar
        if !self.state.validators.contains(&h1.authority) {
            return Err(BlockchainError::InvalidDoubleSignEvidence("Pelaku bukan validator yang terdaftar.".into()));
        }

        // 6. Mencegah replay attack dengan menghash kedua header
        let mut evidence_hasher = Sha256::new();
        evidence_hasher.update(h1.calculate_hash());
        evidence_hasher.update(h2.calculate_hash());
        let evidence_hash = evidence_hasher.finalize().to_vec();

        if self.processed_evidence.contains(&evidence_hash) {
            return Err(BlockchainError::InvalidDoubleSignEvidence("Bukti ini sudah pernah diproses.".into()));
        }

        // Tandai bukti ini sebagai sudah diproses untuk blok berikutnya
        self.processed_evidence.insert(evidence_hash);

        Ok(())
    }

    // --- Untuk memverifikasi tanda tangan pada vote ---
    pub fn verify_vote(&self, vote: &Vote) -> Result<(), BlockchainError> {
        if !self.state.validators.contains(&vote.voter_address) {
            return Err(BlockchainError::NotAValidator);
        }

        let voter_account = self.state.get_account(&vote.voter_address)?
            .ok_or(BlockchainError::NotAValidator)?;

        if !crypto::verify(&voter_account.signing_public_key, &vote.message_hash(), &vote.signature) {
            return Err(BlockchainError::InvalidVoteSignature);
        }
        Ok(())
    }

    // --- Untuk memverifikasi bukti penarikan L2 ---
    // fn verify_withdrawal_proof(
    //     &self,
    //     proof: &crate::WithdrawalProof,
    // ) -> Result<(), BlockchainError> {
    //     // 1. Dapatkan parameter hashing dari sirkuit (ini harus konsisten)
    //     let poseidon_params = crate::l2_circuit::get_poseidon_parameters();
    //     let leaf_crh_params = &poseidon_params; // PoseidonConfig digunakan untuk keduanya
    //     let two_to_one_crh_params = &poseidon_params;

    //     if !self.state.l2_state_root_history.contains(&proof.l2_state_root) {
    //         return Err(BlockchainError::TransactionInvalid(
    //             "Bukti penarikan menggunakan state root L2 yang tidak valid atau sudah usang.".into()
    //         ));
    //     }

    //     // 3. Verifikasi bukti Merkle
    //     let is_member = proof.merkle_path.verify(
    //         &leaf_crh_params,
    //         &two_to_one_crh_params,
    //         &Fr::from_be_bytes_mod_order(&proof.l2_state_root),
    //         &proof.leaf_data,
    //     ).unwrap_or(false);

    //     if !is_member {
    //         return Err(BlockchainError::TransactionInvalid("Bukti Merkle untuk penarikan tidak valid.".into()));
    //     }

    //     // 4. Verifikasi bahwa alamat penerima di leaf sama dengan pengirim transaksi
    //     //    (Ini akan ditambahkan saat kita mengintegrasikannya ke dalam `finalize_and_commit_block`)

    //     Ok(())
    // }
    
    /// Melakukan "dry run" untuk eksekusi transaksi dan menghitung state root berikutnya tanpa meng-commit perubahan ke database utama.
    pub fn calculate_next_state_root(
        &mut self,
        transactions: &[Transaction],
        proposer: Address,
    ) -> Result<Vec<u8>, BlockchainError> {
        let mut session = self.state.create_trie_session(self.state.state_root, COL_TRIE);
        let mut temporary_accounts: HashMap<Address, Account> = HashMap::new();

        let mut simulated_active_sequencers = self.state.active_sequencers.clone();
        let mut simulated_l2_state_root = self.state.l2_state_root.clone();

        let next_id_bytes = self.state.db.get(COL_METADATA, NEXT_PROPOSAL_ID_KEY)?.unwrap_or_else(|| 0u64.to_be_bytes().to_vec());
        let mut simulated_next_proposal_id = u64::from_be_bytes(next_id_bytes.try_into().unwrap());
        let mut simulated_proposals: HashMap<u64, ProposalState> = self.state.get_all_proposals()?
            .into_iter()
            .map(|p| (p.id, p))
            .collect();

        let current_height = self.chain.last().map_or(1, |b| b.header.index + 1);
        let mut validators_to_jail = Vec::new();
        for validator_addr in self.state.validators.iter() {
            let last_seen = self.state.validator_last_seen.get(validator_addr).unwrap_or(&0);
            if current_height > *last_seen && current_height - *last_seen > INACTIVITY_THRESHOLD_BLOCKS {
                validators_to_jail.push(*validator_addr);
            }
        }
        for offender_addr in &validators_to_jail {
            let mut offender_account = temporary_accounts.get(offender_addr)
                .cloned()
                .or_else(|| session.get_account(offender_addr).ok().flatten())
                .unwrap_or_default();
            
            let slash_amount = (offender_account.staked_amount * INACTIVITY_SLASH_PERCENT) / 100;
            if slash_amount > 0 { // Hanya proses jika ada yang di-slash
                offender_account.staked_amount = offender_account.staked_amount.saturating_sub(slash_amount);
                
                // Ambil atau buat akun treasury dengan benar ---
                let mut treasury_account = temporary_accounts.get(&TREASURY_ADDRESS)
                    .cloned()
                    .or_else(|| session.get_account(&TREASURY_ADDRESS).ok().flatten())
                    .unwrap_or_default(); // Aman digunakan di sini
                treasury_account.balance = treasury_account.balance.saturating_add(slash_amount);

                temporary_accounts.insert(*offender_addr, offender_account);
                temporary_accounts.insert(TREASURY_ADDRESS, treasury_account);
            }
        }

        let proposals = self.state.get_all_proposals()?;
        for proposal_state in proposals {
            if !proposal_state.executed && current_height > proposal_state.end_block {
                if proposal_state.yes_votes > proposal_state.no_votes {
                    match &proposal_state.proposal.action {
                        _ => {} // Tangani aksi proposal lain di sini jika ada.
                    }
                }
            }
        }

        let mut total_priority_fees: u64 = 0;
        for tx in transactions {
            let mut sender_account = temporary_accounts.get(&tx.sender)
                .cloned()
                .or_else(|| session.get_account(&tx.sender).ok().flatten())
                .ok_or_else(|| BlockchainError::TransactionInvalid(format!("Akun pengirim tidak ditemukan: {}", hex::encode(tx.sender.as_ref()))))?;

            if tx.nonce != sender_account.nonce {
                return Err(BlockchainError::StaleNonce { expected: sender_account.nonce, got: tx.nonce });
            }

            let last_header = self.chain.last().map(|b| &b.header);
            let base_fee_per_gas = last_header.map_or(INITIAL_BASE_FEE, |h| self.calculate_next_base_fee(h));

            let tip = tx.max_priority_fee_per_gas.min(tx.max_fee_per_gas.saturating_sub(base_fee_per_gas));
            let fee_paid = (base_fee_per_gas + tip) * tx.data.base_gas_cost();
            total_priority_fees += tip * tx.data.base_gas_cost();

            let main_tx_amount = match &tx.data {
                TransactionData::Transfer { amount, .. } |
                TransactionData::Stake { amount, .. } |
                TransactionData::DepositToL2 { amount, .. } => *amount,
                _ => 0,
            };
            let total_deduction = main_tx_amount + fee_paid;

            if sender_account.balance < total_deduction {
                return Err(BlockchainError::InsufficientBalance { has: sender_account.balance, needs: total_deduction });
            }

            sender_account.balance -= total_deduction;
            sender_account.nonce += 1;

            match &tx.data {
                TransactionData::Transfer { recipient, amount } => {
                    let mut recipient_account = temporary_accounts.get(recipient)
                        .cloned()
                        .or_else(|| session.get_account(recipient).ok().flatten())
                        .unwrap_or_default();
                    recipient_account.balance = recipient_account.balance.saturating_add(*amount);
                    temporary_accounts.insert(*recipient, recipient_account);
                }
                TransactionData::Stake { amount } => {
                    sender_account.staked_amount = sender_account.staked_amount.saturating_add(*amount);
                }
                TransactionData::DepositToL2 { amount } => {
                    let mut bridge_account = temporary_accounts.get(&L2_BRIDGE_ADDRESS)
                        .cloned()
                        .or_else(|| session.get_account(&L2_BRIDGE_ADDRESS).ok().flatten())
                        .unwrap_or_default();
                    bridge_account.balance = bridge_account.balance.saturating_add(*amount);
                    temporary_accounts.insert(L2_BRIDGE_ADDRESS, bridge_account);
                }
                TransactionData::ReportDoubleSigning { evidence } => {
                    self.validate_double_sign_evidence(evidence)?;
                    let offender_addr = evidence.header1.authority;
                    let mut offender_account = temporary_accounts.get(&offender_addr)
                        .cloned()
                        .or_else(|| session.get_account(&offender_addr).ok().flatten())
                        .ok_or(BlockchainError::TransactionInvalid("Akun pelaku tidak ditemukan.".into()))?;
                    
                    let slash_amount = offender_account.staked_amount / 10;
                    offender_account.staked_amount = offender_account.staked_amount.saturating_sub(slash_amount);
                    
                    let reward_amount = slash_amount / 2;
                    sender_account.balance = sender_account.balance.saturating_add(reward_amount);

                    temporary_accounts.insert(offender_addr, offender_account);
                }
                TransactionData::CastVote { proposal_id, vote } => {
                    let p_state = simulated_proposals.get_mut(proposal_id)
                        .ok_or(BlockchainError::TransactionInvalid("Proposal tidak ditemukan".into()))?;

                    let vote_weight = sender_account.staked_amount;
                    if *vote { p_state.yes_votes += vote_weight; } else { p_state.no_votes += vote_weight; }
                    p_state.voters.insert(tx.sender);
                }
                TransactionData::SubmitProposal { proposal } => {
                    let proposal_state = ProposalState {
                        id: simulated_next_proposal_id, proposal: proposal.clone(), proposer: tx.sender,
                        start_block: current_height, end_block: current_height + PROPOSAL_VOTING_PERIOD,
                        yes_votes: 0, no_votes: 0, executed: false, voters: HashSet::new(),
                    };
                    simulated_proposals.insert(simulated_next_proposal_id, proposal_state);
                    simulated_next_proposal_id += 1;
                }
                TransactionData::RegisterAsSequencer => {
                    if !self.state.validators.contains(&tx.sender) {
                        return Err(BlockchainError::TransactionInvalid("Hanya validator aktif yang bisa mendaftar sebagai sequencer.".into()));
                    }
                    simulated_active_sequencers.insert(tx.sender);
                }
                TransactionData::DeregisterAsSequencer => {
                    simulated_active_sequencers.remove(&tx.sender);
                }
                TransactionData::SubmitRollupBatch { old_state_root, new_state_root, compressed_batch, 
                    zk_proof, is_test_tx, vrf_output, vrf_proof, dac_signatures } => {
                    // Verifikasi kepemimpinan sequencer
                    if !simulated_active_sequencers.contains(&tx.sender) {
                        return Err(BlockchainError::TransactionInvalid(
                            "Pengirim batch bukan sequencer yang terdaftar.".into()
                        ));
                    }

                    let sequencer_account = temporary_accounts.get(&tx.sender)
                        .cloned()
                        .or_else(|| session.get_account(&tx.sender).ok().flatten())
                        .ok_or_else(|| BlockchainError::TransactionInvalid("Akun sequencer tidak ditemukan.".into()))?;
                    
                        let vrf_pubkey = VrfPublicKey::from_bytes(&sequencer_account.vrf_public_key)
                        .map_err(|_| BlockchainError::VrfVerificationFailed)?;
                    
                    // Verifikasi VRF
                    let last_l1_header = self.chain.last().unwrap();
                    let mut transcript = Transcript::new(b"EVICE_L2_SEQUENCER_ELECTION");
                    transcript.append_message(b"last_l1_hash", &last_l1_header.header.calculate_hash());

                    let vrf_preout = VRFPreOut::from_bytes(vrf_output).map_err(|_| BlockchainError::VrfVerificationFailed)?;
                    let proof = VRFProof::from_bytes(vrf_proof).map_err(|_| BlockchainError::VrfVerificationFailed)?;
                    
                    if vrf_pubkey.vrf_verify(transcript, &vrf_preout, &proof).is_err() {
                        return Err(BlockchainError::VrfVerificationFailed);
                    }

                    let required_dac_signatures = (DATA_AVAILABILITY_COMMITTEE.len() / 2) + 1;
                    let batch_data_hash = Sha256::digest(compressed_batch);
                    let mut valid_dac_approvers = HashSet::new();
                    
                    let dac_addresses: HashSet<Address> = DATA_AVAILABILITY_COMMITTEE.iter()
                        .map(|hex_str| Address(hex::decode(hex_str.trim_start_matches("0x")).unwrap().try_into().unwrap()))
                        .collect();

                    // Di sini kita menggunakan variabel `dac_signatures` yang sebelumnya tidak terpakai
                    for signature in dac_signatures {
                        for dac_address in &dac_addresses {
                            if crypto::verify(dac_address.as_ref(), &batch_data_hash, signature) {
                                valid_dac_approvers.insert(*dac_address);
                                break;
                            }
                        }
                    }

                    if valid_dac_approvers.len() < required_dac_signatures {
                        return Err(BlockchainError::TransactionInvalid(
                            format!("Ketersediaan data tidak terjamin. Persetujuan DAC tidak cukup ({} dari {} dibutuhkan).", valid_dac_approvers.len(), required_dac_signatures)
                        ));
                    }
                    info!("DATA AVAILABILITY: Terkonfirmasi oleh {} anggota DAC.", valid_dac_approvers.len());

                    if old_state_root != &simulated_l2_state_root {
                        return Err(BlockchainError::TransactionInvalid(
                            "Batch L2 dibangun di atas state root yang usang atau tidak valid.".into()
                        ));
                    }
                    
                    if !is_test_tx {
                        // Validasi ZK Proof (operasi read-only)
                        let proof = Proof::deserialize_uncompressed(&zk_proof[..]).map_err(|e| BlockchainError::TransactionInvalid(format!("Gagal deserialize bukti ZK: {}", e)))?;
                        let old_root_fr = Fr::from_be_bytes_mod_order(&simulated_l2_state_root);
                        let new_root_fr = Fr::from_be_bytes_mod_order(new_state_root);
                        let public_inputs = &[old_root_fr, new_root_fr];
                        if !Groth16::<Bls12_381>::verify(&self.l2_verifying_key, public_inputs, &proof)? {
                            return Err(BlockchainError::TransactionInvalid("Bukti ZK tidak valid!".into()));
                        }
                    }
                    // Perbarui L2 state root yang disimulasikan
                    simulated_l2_state_root = new_state_root.clone();
                }
                // Logika untuk memproses pembaruan kunci VRF.
                TransactionData::UpdateVrfKey { new_vrf_public_key } => {
                    if !self.state.validators.contains(&tx.sender) {
                        return Err(BlockchainError::TransactionInvalid("Hanya validator aktif yang dapat memperbarui kunci VRF.".into()));
                    }
                    sender_account.vrf_public_key = *new_vrf_public_key;
                }
                // TransactionData::WithdrawFromL2 { amount, withdrawal_proof } => {
                //     // Verifikasi bukti secara kriptografis
                //     self.verify_withdrawal_proof(withdrawal_proof)?;
                    
                //     // Verifikasi konsistensi data
                //     let sender_pubkey_fr = Fr::from_be_bytes_mod_order(tx.sender.as_ref());
                //     if withdrawal_proof.leaf_data[0] != sender_pubkey_fr {
                //         return Err(BlockchainError::TransactionInvalid("Alamat penerima di bukti penarikan tidak cocok dengan pengirim transaksi.".into()));
                //     }
                //     if withdrawal_proof.leaf_data[1] != Fr::from(*amount) {
                //          return Err(BlockchainError::TransactionInvalid("Jumlah di bukti penarikan tidak cocok dengan jumlah transaksi.".into()));
                //     }

                //     // --- Ganti transfer langsung dengan panggilan ke fungsi aman ---
                //     self.process_bridge_withdrawal(
                //         &mut trie,
                //         *amount,
                //         &mut sender_account, // `sender_account` sudah mutable
                //     )?;
                // }
                TransactionData::WithdrawFromTreasury { recipient, amount, approvals } => {
                    // CATATAN: Logika ini adalah cerminan dari `finalize_and_commit_block`
                    // tetapi dimodifikasi untuk bekerja dalam simulasi "dry run".

                    // 1. Verifikasi tanda tangan (operasi read-only, tidak perlu diubah)
                    let mut message_to_sign = Vec::new();
                    message_to_sign.extend_from_slice(recipient.as_ref());
                    message_to_sign.extend_from_slice(&amount.to_be_bytes());
                    let message_hash = sha2::Sha256::digest(&message_to_sign);

                    let required_approvals = (DEVELOPER_COMMITTEE.len() / 2) + 1;
                    let mut valid_approvers = HashSet::new();

                    let committee_addresses: HashSet<Address> = DEVELOPER_COMMITTEE.iter()
                        .map(|hex_str| {
                            let clean_hex = hex_str.trim_start_matches("0x");
                            let bytes = hex::decode(clean_hex).expect("Invalid hex in DEVELOPER_COMMITTEE");
                            Address(bytes.try_into().expect("Invalid address length in DEVELOPER_COMMITTEE"))
                        })
                        .collect();

                    for signature in approvals {
                        for dev_address in &committee_addresses {
                            if crypto::verify(dev_address.as_ref(), &message_hash, signature) {
                                valid_approvers.insert(*dev_address);
                                break;
                            }
                        }
                    }

                    // 2. Periksa ambang batas persetujuan
                    if valid_approvers.len() < required_approvals {
                        // Jika tidak valid, kembalikan error agar transaksi ditolak.
                        return Err(BlockchainError::TransactionInvalid(
                            format!("Persetujuan dari komite pengembang tidak mencukupi (dibutuhkan {}, hanya ada {}).", required_approvals, valid_approvers.len())
                        ));
                    }
                    
                    // 3. Lakukan transfer dana dalam state sementara
                    // Ambil akun treasury menggunakan pola state sementara
                    let mut treasury_account = temporary_accounts.get(&TREASURY_ADDRESS)
                        .cloned()
                        .or_else(|| session.get_account(&TREASURY_ADDRESS).ok().flatten())
                        .ok_or(BlockchainError::LogicError("Akun treasury tidak ditemukan.".into()))?;

                    if treasury_account.balance < *amount {
                        return Err(BlockchainError::InsufficientBalance { has: treasury_account.balance, needs: *amount });
                    }
                    treasury_account.balance = treasury_account.balance.saturating_sub(*amount);

                    // Ambil akun penerima menggunakan pola state sementara
                    let mut recipient_account = temporary_accounts.get(recipient)
                        .cloned()
                        .or_else(|| session.get_account(recipient).ok().flatten())
                        .unwrap_or_default();
                    recipient_account.balance = recipient_account.balance.saturating_add(*amount);

                    // Simpan kembali kedua akun yang telah dimodifikasi ke dalam state sementara
                    temporary_accounts.insert(TREASURY_ADDRESS, treasury_account);
                    temporary_accounts.insert(*recipient, recipient_account);
                }
                TransactionData::DeployContract { code } => {
                    if code.is_empty() {
                        return Err(BlockchainError::TransactionInvalid("Kode kontrak tidak boleh kosong.".into()));
                    }
                    let contract_address_bytes = {
                        let mut data = Vec::new();
                        data.extend_from_slice(tx.sender.as_ref());
                        data.extend_from_slice(&sender_account.nonce.to_be_bytes());
                        KeccakHasher::hash(&data)
                    };
                    let contract_address = Address(contract_address_bytes.as_slice()[..ADDRESS_SIZE].try_into().unwrap());

                    // Buat trie penyimpanan kosong untuk kontrak baru
                    let empty_storage_session = self.state.create_trie_session(Default::default(), COL_CONTRACT_STORAGE);
                    let initial_storage_root = empty_storage_session.commit()?;
                    let code_hash = KeccakHasher::hash(code).to_vec();
                    
                    let contract_account = Account {
                        code_hash: Some(code_hash.clone()),
                        storage_root: Some(initial_storage_root.to_vec()),
                        ..Default::default()
                    };
                    temporary_accounts.insert(contract_address, contract_account);
                }
                TransactionData::CallContract { contract_address, call_data } => {
                    let mut contract_account = temporary_accounts.get(contract_address)
                        .cloned()
                        .or_else(|| session.get_account(contract_address).ok().flatten())
                        .ok_or_else(|| BlockchainError::TransactionInvalid("Akun kontrak tidak ditemukan".into()))?;

                    let code_hash = contract_account.code_hash.clone().ok_or_else(|| BlockchainError::TransactionInvalid("Akun bukan sebuah kontrak.".into()))?;
                    let code = self.state.db.get(COL_CONTRACT_CODE, &code_hash)?.ok_or_else(|| BlockchainError::TransactionInvalid("Kode kontrak tidak ditemukan di DB".into()))?;
                    
                    let gas_limit = 50_000_000;
                    let result = wasm_runtime::execute_contract(
                        &self.state, &code, contract_account.storage_root.clone(), tx.sender,
                        call_data, gas_limit, current_height, // atau timestamp
                    )?;
                    
                    contract_account.storage_root = Some(result.new_storage_root);
                    
                    for (recipient, amount) in result.requested_transfers {
                        if contract_account.balance < amount {
                            return Err(BlockchainError::LogicError("Kontrak mencoba mentransfer lebih banyak dari saldonya.".into()));
                        }
                        contract_account.balance -= amount;
                        
                        let mut recipient_account = temporary_accounts.get(&recipient)
                            .cloned()
                            .or_else(|| session.get_account(&recipient).ok().flatten())
                            .unwrap_or_default();
                        recipient_account.balance += amount;
                        temporary_accounts.insert(recipient, recipient_account);
                    }

                    temporary_accounts.insert(*contract_address, contract_account);
                }
            }
            temporary_accounts.insert(tx.sender, sender_account);
        }

        const BLOCK_REWARD: u64 = 1_000_000;
        const TREASURY_ALLOCATION_PERCENT: u64 = 10;

        let treasury_reward = (BLOCK_REWARD * TREASURY_ALLOCATION_PERCENT) / 100;
        let proposer_reward = BLOCK_REWARD - treasury_reward;

        let mut treasury_account = temporary_accounts.get(&TREASURY_ADDRESS)
            .cloned()
            .or_else(|| session.get_account(&TREASURY_ADDRESS).ok().flatten())
            .unwrap_or_default();
        treasury_account.balance = treasury_account.balance.saturating_add(treasury_reward);
        temporary_accounts.insert(TREASURY_ADDRESS, treasury_account);

        let mut proposer_account = temporary_accounts.get(&proposer)
            .cloned()
            .or_else(|| session.get_account(&proposer).ok().flatten())
            .unwrap_or_default();
        proposer_account.balance = proposer_account.balance.saturating_add(proposer_reward + total_priority_fees);
        temporary_accounts.insert(proposer, proposer_account);

        let mut sorted_addresses: Vec<Address> = temporary_accounts.keys().cloned().collect();
        sorted_addresses.sort_by(|a, b| a.0.cmp(&b.0));

        for address in sorted_addresses {
            if let Some(account) = temporary_accounts.get(&address) {
                session.set_account(&address, account)?;
            }
        }

        let new_root = session.root();
        Ok(new_root.as_ref().to_vec())
    }

    pub fn process_block_proposal(&mut self, block: &Block) -> Result<(), BlockchainError> {
        let last_header = self.chain.last().map(|b| &b.header);
        // Node baru mungkin belum punya blok, jadi `last_header` bisa None
        let expected_index = last_header.map_or(0, |h| h.index + 1);
        
        // Izinkan sinkronisasi blok genesis
        if block.header.index == 0 {
             // Lakukan validasi minimal untuk blok genesis di sini jika perlu
            return Ok(());
        }

        if block.header.index != expected_index {
            return Err(BlockchainError::InvalidIndex { expected: expected_index, got: block.header.index });
        }
        
        let expected_prev_hash = last_header.map_or(vec![0; 32], |h| h.calculate_hash());       
        if block.header.prev_hash != expected_prev_hash { return Err(BlockchainError::PreviousHashMismatch); }
        
        if !self.state.validators.contains(&block.header.authority) { return Err(BlockchainError::NotAValidator); }
        
        let proposer_account = self.state.get_account(&block.header.authority)?
            .ok_or(BlockchainError::NotAValidator)?;

        if !crypto::verify(&proposer_account.signing_public_key, &block.header.message_to_sign(),  &block.header.signature) {
            return Err(BlockchainError::InvalidSignature);
        }

        let calculated_state_root = self.calculate_next_state_root(&block.transactions, block.header.authority)?;
        if calculated_state_root != block.header.state_root {
            return Err(BlockchainError::StateRootMismatch {
                expected: hex::encode(&block.header.state_root),
                got: hex::encode(&calculated_state_root),
            });
        }

        Ok(())
    }

    /// Menghitung base_fee dinamis untuk blok berikutnya berdasarkan header blok sebelumnya.
    pub fn calculate_next_base_fee(&self, parent: &BlockHeader) -> u64 {
        const TARGET_GAS_USED: u64 = 15_000_000; // Target gas (misal 50% dari blok maks)
        const MAX_CHANGE_DENOMINATOR: u64 = 8;    // Seberapa cepat base_fee berubah

        let parent_gas_used = parent.gas_used;
        let parent_base_fee = parent.base_fee_per_gas;

        if parent_gas_used == TARGET_GAS_USED {
            return parent_base_fee;
        }

        if parent_gas_used > TARGET_GAS_USED {
            // Jika blok sebelumnya lebih penuh dari target, naikkan base_fee
            let gas_diff = parent_gas_used - TARGET_GAS_USED;
            // Rumus: new_base_fee = parent_base_fee + (parent_base_fee * gas_diff / TARGET_GAS_USED) / MAX_CHANGE_DENOMINATOR
            let delta = (parent_base_fee * gas_diff / TARGET_GAS_USED) / MAX_CHANGE_DENOMINATOR;
            parent_base_fee + delta.max(1) // Kenaikan minimal 1 wei
        } else {
            // Jika blok sebelumnya lebih kosong dari target, turunkan base_fee
            let gas_diff = TARGET_GAS_USED - parent_gas_used;
            let delta = (parent_base_fee * gas_diff / TARGET_GAS_USED) / MAX_CHANGE_DENOMINATOR;
            parent_base_fee.saturating_sub(delta)
        }
    }

    pub fn create_block(
        &self,
        authority_keypair: &KeyPair,
        transactions: Vec<Transaction>,
        state_root: Vec<u8>,
        vrf_output: Vec<u8>,
        vrf_proof: Vec<u8>,
        timestamp: u128,
        round: u64,
    ) -> Block {
        let last_header = self.chain.last().map(|b| &b.header);
        let new_index = last_header.map_or(0, |h| h.index + 1);
        let prev_hash = last_header.map_or(vec![0; 32], |h| h.calculate_hash());
        let base_fee_per_gas = last_header.map_or(INITIAL_BASE_FEE, |h| self.calculate_next_base_fee(h));
        let gas_used = transactions.iter().map(|tx| tx.data.base_gas_cost()).sum();

        // Hitung hash gabungan dari semua data batch L2.
        let l2_transactions_hash = {
            let mut l2_data = Vec::new();
            for tx in &transactions {
                if let TransactionData::SubmitRollupBatch { compressed_batch, .. } = &tx.data {
                    l2_data.extend_from_slice(compressed_batch);
                }
            }

            // Jika tidak ada data L2, hasilnya adalah None.
            // Jika ada, hasilnya adalah Some(hash).
            if l2_data.is_empty() {
                None
            } else {
                let mut hasher = Sha256::new();
                hasher.update(&l2_data);
                Some(hasher.finalize().to_vec())
            }
        };

        let mut header = BlockHeader {
            index: new_index,
            timestamp,
            prev_hash,
            state_root,
            transactions_root: Block::calculate_transactions_root(&transactions),
            l2_transactions_hash,
            authority: public_key_to_address(&authority_keypair.public_key_bytes()),
            gas_used,
            base_fee_per_gas,
            signature: [0; SIGNATURE_SIZE],
        };

        header.signature = authority_keypair.sign(&header.message_to_sign());

        Block {
            header,
            transactions,
            round,
            vrf_output,
            vrf_proof,
        }
    }

    // // Fungsi helper untuk mengelola bridge, mensimulasikan smart contract
    // fn process_bridge_withdrawal(
    //     &self,
    //     trie: &mut TrieDBMut<EviceTrieLayout>,
    //     withdrawal_amount: u64,
    //     recipient_account: &mut Account,
    // ) -> Result<(), BlockchainError> {
    //     const DAILY_WITHDRAWAL_LIMIT: u64 = 1_000_000; // Batas penarikan per hari: 1 juta token
        
    //     let bridge_hashed_key = KeccakHasher::hash(L2_BRIDGE_ADDRESS.as_ref());
    //     let mut bridge_account: Account = trie.get(&bridge_hashed_key)?
    //         .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
    //         .unwrap_or_default();
        
    //     // Kita gunakan field yang ada secara kreatif untuk menyimpan state kontrak:
    //     // `nonce` -> timestamp hari terakhir penarikan (misal, jumlah hari sejak epoch)
    //     // `staked_amount` -> total dana yang sudah ditarik pada hari tersebut
        
    //     let current_day = self.chain.last().map_or(0, |b| b.header.timestamp / (1000 * 60 * 60 * 24)) as u64;
    //     let last_withdrawal_day = bridge_account.nonce;

    //     let mut withdrawn_today = if current_day == last_withdrawal_day {
    //         bridge_account.staked_amount
    //     } else {
    //         // Hari baru, reset counter penarikan
    //         0
    //     };

    //     if withdrawn_today + withdrawal_amount > DAILY_WITHDRAWAL_LIMIT {
    //         let msg = format!(
    //             "Batas penarikan harian bridge terlampaui. Sisa limit: {}",
    //             DAILY_WITHDRAWAL_LIMIT.saturating_sub(withdrawn_today)
    //         );
    //         return Err(BlockchainError::TransactionInvalid(msg));
    //     }
        
    //     if bridge_account.balance < withdrawal_amount {
    //         return Err(BlockchainError::InsufficientBalance { has: bridge_account.balance, needs: withdrawal_amount });
    //     }

    //     // Lakukan transfer
    //     bridge_account.balance -= withdrawal_amount;
    //     recipient_account.balance += withdrawal_amount;

    //     // Perbarui state "storage" kontrak bridge
    //     withdrawn_today += withdrawal_amount;
    //     bridge_account.staked_amount = withdrawn_today;
    //     bridge_account.nonce = current_day;

    //     // Simpan kembali state bridge ke trie
    //     trie.insert(&bridge_hashed_key, &bincode::serialize(&bridge_account)?)?;
    //     info!("BRIDGE: Penarikan {} berhasil. Total ditarik hari ini: {}", withdrawal_amount, withdrawn_today);
    //     Ok(())
    // }

    fn process_governance_proposals(
        &self,
        current_block_height: u64,
        _trie: &mut TrieDBMut<EviceTrieLayout>,
        governance_ops: &mut Vec<(u8, Vec<u8>, Option<Vec<u8>>)>
    ) -> Result<(), BlockchainError> {
        // Dapatkan semua proposal dari DB (Anda perlu membuat fungsi helper di StateMachine untuk ini)
        let proposals = self.state.get_all_proposals()?;

        for mut proposal_state in proposals {
            // Cek jika voting sudah selesai dan proposal belum dieksekusi
            if !proposal_state.executed && current_block_height > proposal_state.end_block {
                info!("GOVERNANCE: Memproses proposal #{} yang telah selesai.", proposal_state.id);
                proposal_state.executed = true;

                // Tentukan pemenang
                if proposal_state.yes_votes > proposal_state.no_votes {
                    info!("GOVERNANCE: Proposal #{} disetujui. Mengeksekusi tindakan...", proposal_state.id);
                    
                    match &proposal_state.proposal.action {
                        // ProposalAction::FundTransfer { recipient, amount } => {
                        //     let treasury_hashed_key = KeccakHasher::hash(TREASURY_ADDRESS.as_ref());
                        //     let mut treasury_account: Account = trie.get(&treasury_hashed_key)?
                        //         .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
                        //         .unwrap_or_default();
                            
                        //     if treasury_account.balance >= *amount {
                        //         treasury_account.balance -= *amount;

                        //         let recipient_hashed_key = KeccakHasher::hash(recipient.as_ref());
                        //         let mut recipient_account: Account = trie.get(&recipient_hashed_key)?
                        //             .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
                        //             .unwrap_or_default();
                                
                        //         recipient_account.balance += *amount;

                        //         trie.insert(&treasury_hashed_key, &bincode::serialize(&treasury_account)?)?;
                        //         trie.insert(&recipient_hashed_key, &bincode::serialize(&recipient_account)?)?;
                        //         info!("TREASURY: Berhasil mentransfer {} dari kas ke alamat {}", amount, hex::encode(recipient.as_ref()));
                        //     } else {
                        //         warn!("TREASURY: Eksekusi proposal #{} gagal: dana kas tidak mencukupi.", proposal_state.id);
                        //     }
                        // }
                        // Tambahkan kasus lain di sini (misal, UpdateParameter)
                        _ => {}
                    }
                } else {
                    info!("GOVERNANCE: Proposal #{} ditolak.", proposal_state.id);
                }

                // Simpan state proposal yang sudah diperbarui (executed = true)
                governance_ops.push((
                    COL_GOVERNANCE,
                    proposal_state.id.to_be_bytes().to_vec(),
                    Some(bincode::serialize(&proposal_state)?),
                ));
            }
        }
        Ok(())
    }

    // Untuk mengaplikasikan blok yang sudah final
    pub fn finalize_and_commit_block(&mut self, block: Block) -> Result<Vec<Transaction>, BlockchainError> {
        // Berikan perlakuan khusus untuk Blok Genesis (akta kelahiran)
        if block.header.index == 0 {
            info!("GENESIS SYNC: Menerima dan menyimpan Blok #0 dari jaringan.");
            
            // 1. Simpan blok ke database
            let block_op = (
                COL_BLOCKS,
                0u64.to_be_bytes().to_vec(),
                Some(bincode::serialize(&block).unwrap())
            );
            
            // 2. Terima state root dari genesis sebagai kebenaran, jangan verifikasi ulang.
            //    Ini akan menjadi fondasi untuk semua blok berikutnya.
            let state_root_op = (
                COL_METADATA,
                STATE_ROOT_KEY.to_vec(),
                Some(block.header.state_root.clone())
            );
            
            // Simpan ke DB
            self.state.db.commit(vec![block_op, state_root_op])?;
            
            // 3. Perbarui state di dalam memori
            self.state.state_root = block.header.state_root.as_slice().try_into().unwrap();
            
            // Setelah genesis diterima, state `validators` di database sudah ada,
            // tetapi state di memori kita masih kosong. Muat ulang dari DB.
            if let Ok(Some(encoded_validators)) = self.state.db.get(COL_METADATA, VALIDATORS_KEY) {
                if let Ok(validators) = bincode::deserialize(&encoded_validators) {
                    info!("GENESIS SYNC: Memuat ulang set validator dari state yang disinkronkan.");
                    self.state.validators = validators;
                }
            }

            self.chain.push(block);
            // Tidak ada transaksi yang diproses di genesis, kembalikan vektor kosong
            return Ok(Vec::new());
        }

        let mut current_l2_state_root = self.state.l2_state_root.clone();
        let mut transactional_state_root = self.state.state_root;
        let mut trie_db = ParityDbTrieBackend::new(self.state.db.clone(), COL_TRIE);
        let mut trie = TrieDBMutBuilder::<crate::EviceTrieLayout>::from_existing(
            trie_db.as_hash_db_mut(), &mut transactional_state_root
        ).build();

        let mut total_priority_fees: u64 = 0;
        let mut total_base_fees_to_burn: u64 = 0;
        let mut l2_batch_ops = Vec::new();
        let mut governance_ops = Vec::new();
        let mut db_ops = Vec::new(); 
        self.process_governance_proposals(block.header.index, &mut trie, &mut governance_ops)?;

        // ===================================================================
        //          Logika Pengecekan Aktivitas dan Slashing Validator
        // ===================================================================
        let current_height = block.header.index;
        let proposer = block.header.authority;
        let mut validators_to_jail = Vec::new();

        self.state.validator_last_seen.insert(proposer, current_height);

        let mut sorted_validators: Vec<Address> = self.state.validators.iter().cloned().collect();
        sorted_validators.sort_by(|a, b| a.0.cmp(&b.0));

        for validator_addr in sorted_validators {
            let last_seen = self.state.validator_last_seen.get(&validator_addr).unwrap_or(&0);
            if current_height > *last_seen && current_height - *last_seen > INACTIVITY_THRESHOLD_BLOCKS {
                warn!(
                    "VALIDATOR INACTIVITY: Validator {} terakhir terlihat di blok #{}. Melebihi ambang batas {} blok. Akan dipenjara dan di-slash.",
                    hex::encode(validator_addr.as_ref()),
                    last_seen,
                    INACTIVITY_THRESHOLD_BLOCKS
                );
                validators_to_jail.push(validator_addr);
            }
        }

        // Urutkan daftar yang akan dihukum untuk menjamin urutan eksekusi
        validators_to_jail.sort_by(|a, b| a.0.cmp(&b.0));

        // Terapkan hukuman (penjara dan slash) pada validator yang tidak aktif.
        for offender_addr in &validators_to_jail {
            let offender_hashed_key = KeccakHasher::hash(offender_addr.as_ref());
            if let Some(mut offender_account) = trie.get(&offender_hashed_key)?
                .map(|d| bincode::deserialize::<Account>(&d[..]).unwrap_or_default())
            {
                let slash_amount = (offender_account.staked_amount * INACTIVITY_SLASH_PERCENT) / 100;
                if slash_amount > 0 {
                    offender_account.staked_amount = offender_account.staked_amount.saturating_sub(slash_amount);
                    
                    let treasury_hashed_key = KeccakHasher::hash(TREASURY_ADDRESS.as_ref());
                    let mut treasury_account: Account = trie.get(&treasury_hashed_key)?
                        .map(|d| bincode::deserialize::<Account>(&d[..]).unwrap_or_default())
                        .unwrap_or_default();
                    treasury_account.balance = treasury_account.balance.saturating_add(slash_amount);

                    trie.insert(&offender_hashed_key, &bincode::serialize(&offender_account)?)?;
                    trie.insert(&treasury_hashed_key, &bincode::serialize(&treasury_account)?)?;
                    info!("SLASHED (INACTIVITY): Stake validator {} dikurangi sebesar {}.", hex::encode(offender_addr.as_ref()), slash_amount);
                }
            }
        }

        for tx in &block.transactions {
            let sender_hashed_key = KeccakHasher::hash(tx.sender.as_ref());
            let mut sender_account: Account = trie.get(&sender_hashed_key)?
                .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
                .ok_or_else(|| BlockchainError::TransactionInvalid("Akun pengirim tidak ditemukan".into()))?;

            if !crypto::verify(
                &sender_account.signing_public_key, // Gunakan kunci penuh 1312-byte dari state
                &tx.message_hash(),
                &tx.signature
            ) {
                warn!("TRANSACTION COMMIT FAILED: Tanda tangan tidak valid untuk tx dari {}", hex::encode(tx.sender.as_ref()));
                return Err(BlockchainError::InvalidSignature);
            }

            // --- Logika Pengurangan Tunggal yang Benar ---
            let tip = tx.max_priority_fee_per_gas.min(tx.max_fee_per_gas.saturating_sub(block.header.base_fee_per_gas));
            let fee_paid = (block.header.base_fee_per_gas + tip) * tx.data.base_gas_cost();
            let main_tx_amount = match &tx.data {
                TransactionData::Transfer { amount, .. } |
                TransactionData::Stake { amount, .. } |
                TransactionData::DepositToL2 { amount, .. } => *amount,
                _ => 0,
            };
            let total_deduction = main_tx_amount + fee_paid;

            if sender_account.balance < total_deduction {
                return Err(BlockchainError::InsufficientBalance { has: sender_account.balance, needs: total_deduction });
            }
            
            sender_account.balance -= total_deduction;
            sender_account.nonce += 1;

            total_priority_fees += tip * tx.data.base_gas_cost();
            total_base_fees_to_burn += block.header.base_fee_per_gas * tx.data.base_gas_cost();

            // --- Proses Logika Spesifik Transaksi ---
            match &tx.data {
                TransactionData::Transfer { recipient, amount } => {
                    let recipient_hashed_key = KeccakHasher::hash(recipient.as_ref());
                    let mut recipient_account: Account = trie.get(&recipient_hashed_key)?.map(|d| bincode::deserialize(&d[..]).unwrap_or_default()).unwrap_or_default();
                    recipient_account.balance += *amount;
                    trie.insert(&recipient_hashed_key, &bincode::serialize(&recipient_account)?)?;
                }
                TransactionData::Stake { amount } => {
                    sender_account.staked_amount += *amount;
                    if sender_account.staked_amount >= MINIMUM_STAKE {
                        self.state.validators.insert(tx.sender);
                    }
                }
                TransactionData::ReportDoubleSigning { evidence } => {
                    self.validate_double_sign_evidence(evidence)?;
                    let offender_addr = evidence.header1.authority;
                    let offender_hashed_key = KeccakHasher::hash(offender_addr.as_ref());
                    let mut offender_account: Account = trie.get(&offender_hashed_key)?
                        .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
                        .ok_or(BlockchainError::TransactionInvalid("Akun pelaku tidak ditemukan.".into()))?;
                    
                    let slash_amount = offender_account.staked_amount / 10;
                    offender_account.staked_amount = offender_account.staked_amount.saturating_sub(slash_amount);
                    
                    let reward_amount = slash_amount / 2;
                    sender_account.balance = sender_account.balance.saturating_add(reward_amount);

                    trie.insert(&offender_hashed_key, &bincode::serialize(&offender_account)?)?;
                    info!("SLASHED: Stake validator {} dikurangi sebesar {}.", hex::encode(offender_addr.as_ref()), slash_amount);
                }
                TransactionData::CastVote { proposal_id, vote } => {
                    let mut p_state: ProposalState = self.state.db.get(COL_GOVERNANCE, &proposal_id.to_be_bytes())?
                        .map(|bytes| bincode::deserialize(&bytes[..]).unwrap())
                        .ok_or(BlockchainError::TransactionInvalid("Proposal tidak ditemukan".into()))?;

                    let vote_weight = sender_account.staked_amount;
                    if *vote { p_state.yes_votes += vote_weight; } else { p_state.no_votes += vote_weight; }
                    p_state.voters.insert(tx.sender);

                    governance_ops.push((
                        COL_GOVERNANCE,
                        proposal_id.to_be_bytes().to_vec(),
                        Some(bincode::serialize(&p_state)?),
                    ));
                }
                TransactionData::SubmitProposal { proposal } => {
                    let next_id_bytes = self.state.db.get(COL_METADATA, NEXT_PROPOSAL_ID_KEY)?.unwrap_or_else(|| 0u64.to_be_bytes().to_vec());
                    let mut next_proposal_id = u64::from_be_bytes(next_id_bytes.try_into().unwrap());

                    let proposal_state = ProposalState {
                        id: next_proposal_id, proposal: proposal.clone(), proposer: tx.sender,
                        start_block: block.header.index, end_block: block.header.index + PROPOSAL_VOTING_PERIOD,
                        yes_votes: 0, no_votes: 0, executed: false, voters: HashSet::new(),
                    };
                    governance_ops.push((
                        COL_GOVERNANCE,
                        next_proposal_id.to_be_bytes().to_vec(),
                        Some(bincode::serialize(&proposal_state)?),
                    ));

                    next_proposal_id += 1;
                    governance_ops.push((
                        COL_METADATA,
                        NEXT_PROPOSAL_ID_KEY.to_vec(),
                        Some(next_proposal_id.to_be_bytes().to_vec()),
                    ));
                }
                TransactionData::DepositToL2 { amount } => {
                    let bridge_hashed_key = KeccakHasher::hash(L2_BRIDGE_ADDRESS.as_ref());
                    let mut bridge_account: Account = trie.get(&bridge_hashed_key)?.map(|d| bincode::deserialize(&d[..]).unwrap_or_default()).unwrap_or_default();
                    bridge_account.balance += *amount;
                    trie.insert(&bridge_hashed_key, &bincode::serialize(&bridge_account)?)?;
                }
                TransactionData::RegisterAsSequencer => {
                    if !self.state.validators.contains(&tx.sender) { // Gunakan state.validators
                        return Err(BlockchainError::TransactionInvalid(
                            "Hanya validator aktif yang bisa mendaftar sebagai sequencer.".into()
                        ));
                    }
                    info!("SEQUENCER MGMT: Validator {} mendaftar sebagai sequencer.", hex::encode(tx.sender.as_ref()));
                    self.state.active_sequencers.insert(tx.sender);
                }
                TransactionData::DeregisterAsSequencer => {
                    info!("SEQUENCER MGMT: Akun {} berhenti menjadi sequencer.", hex::encode(tx.sender.as_ref()));
                    self.state.active_sequencers.remove(&tx.sender);
                }
                TransactionData::SubmitRollupBatch { old_state_root, new_state_root, compressed_batch, 
                    zk_proof, is_test_tx, vrf_output, vrf_proof, dac_signatures } => {
                    // Verifikasi kepemimpinan sequencer
                    if !self.state.active_sequencers.contains(&tx.sender) {
                        return Err(BlockchainError::TransactionInvalid(
                            "Pengirim batch bukan sequencer yang terdaftar.".into()
                        ));
                    }

                    // Dapatkan VRF public key dari akun sequencer
                    let sequencer_hashed_key = KeccakHasher::hash(tx.sender.as_ref());
                    let sequencer_account: Account = trie.get(&sequencer_hashed_key)?
                        .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
                        .ok_or_else(|| BlockchainError::TransactionInvalid("Akun sequencer tidak ditemukan.".into()))?;
                    
                    let vrf_pubkey = VrfPublicKey::from_bytes(&sequencer_account.vrf_public_key)
                        .map_err(|_| BlockchainError::VrfVerificationFailed)?;
                    
                    // Verifikasi VRF
                    let last_l1_header = self.chain.last().unwrap();
                    let mut transcript = Transcript::new(b"EVICE_L2_SEQUENCER_ELECTION");
                    transcript.append_message(b"last_l1_hash", &last_l1_header.header.calculate_hash());

                    let vrf_preout = VRFPreOut::from_bytes(vrf_output).map_err(|_| BlockchainError::VrfVerificationFailed)?;
                    let proof = VRFProof::from_bytes(vrf_proof).map_err(|_| BlockchainError::VrfVerificationFailed)?;
                    
                    if vrf_pubkey.vrf_verify(transcript, &vrf_preout, &proof).is_err() {
                        return Err(BlockchainError::VrfVerificationFailed);
                    }

                    let required_dac_signatures = (DATA_AVAILABILITY_COMMITTEE.len() / 2) + 1;
                    let batch_data_hash = Sha256::digest(compressed_batch);
                    let mut valid_dac_approvers = HashSet::new();
                    
                    let dac_addresses: HashSet<Address> = DATA_AVAILABILITY_COMMITTEE.iter()
                        .map(|hex_str| Address(hex::decode(hex_str.trim_start_matches("0x")).unwrap().try_into().unwrap()))
                        .collect();

                    // Di sini kita menggunakan variabel `dac_signatures` yang sebelumnya tidak terpakai
                    for signature in dac_signatures {
                        for dac_address in &dac_addresses {
                            if crypto::verify(dac_address.as_ref(), &batch_data_hash, signature) {
                                valid_dac_approvers.insert(*dac_address);
                                break;
                            }
                        }
                    }

                    if valid_dac_approvers.len() < required_dac_signatures {
                        return Err(BlockchainError::TransactionInvalid(
                            format!("Ketersediaan data tidak terjamin. Persetujuan DAC tidak cukup ({} dari {} dibutuhkan).", valid_dac_approvers.len(), required_dac_signatures)
                        ));
                    }
                    info!("DATA AVAILABILITY: Terkonfirmasi oleh {} anggota DAC.", valid_dac_approvers.len());

                    // Hanya verifikasi bukti jika ini BUKAN transaksi tes
                    if !is_test_tx {
                        let proof = Proof::deserialize_uncompressed(&zk_proof[..]).map_err(|e| BlockchainError::TransactionInvalid(format!("Gagal deserialize bukti ZK: {}", e)))?;
                        
                        let old_root_fr = Fr::from_be_bytes_mod_order(old_state_root);
                        let new_root_fr = Fr::from_be_bytes_mod_order(new_state_root);
                        
                        let public_inputs = &[old_root_fr, new_root_fr];
                        
                        if !Groth16::<Bls12_381>::verify(&self.l2_verifying_key, public_inputs, &proof)? {
                            return Err(BlockchainError::TransactionInvalid("Bukti ZK tidak valid!".into()));
                        }
                    }
                    current_l2_state_root = new_state_root.clone();

                    // Simpan data batch L2 ke database.
                    // Kuncinya adalah nomor blok L1.
                    l2_batch_ops.push((
                        COL_L2_BATCHES,
                        block.header.index.to_be_bytes().to_vec(),
                        Some(compressed_batch.clone()),
                    ));
                }
                // Logika untuk memproses pembaruan kunci VRF.
                TransactionData::UpdateVrfKey { new_vrf_public_key } => {
                    // Keamanan: Hanya validator aktif yang bisa memperbarui kuncinya.
                    if !self.state.validators.contains(&tx.sender) {
                        return Err(BlockchainError::TransactionInvalid(
                            "Hanya validator aktif yang dapat memperbarui kunci VRF.".into()
                        ));
                    }
                    sender_account.vrf_public_key = *new_vrf_public_key;
                    info!("SECURITY: Validator {} berhasil memperbarui kunci VRF.", hex::encode(tx.sender.as_ref()));
                }
                // TransactionData::WithdrawFromL2 { amount, withdrawal_proof } => {
                //     // Verifikasi bukti secara kriptografis
                //     self.verify_withdrawal_proof(withdrawal_proof)?;
                    
                //     // Verifikasi konsistensi data
                //     let sender_pubkey_fr = Fr::from_be_bytes_mod_order(tx.sender.as_ref());
                //     if withdrawal_proof.leaf_data[0] != sender_pubkey_fr {
                //         return Err(BlockchainError::TransactionInvalid("Alamat penerima di bukti penarikan tidak cocok dengan pengirim transaksi.".into()));
                //     }
                //     if withdrawal_proof.leaf_data[1] != Fr::from(*amount) {
                //          return Err(BlockchainError::TransactionInvalid("Jumlah di bukti penarikan tidak cocok dengan jumlah transaksi.".into()));
                //     }

                //     // --- Ganti transfer langsung dengan panggilan ke fungsi aman ---
                //     self.process_bridge_withdrawal(
                //         &mut trie,
                //         *amount,
                //         &mut sender_account, // `sender_account` sudah mutable
                //     )?;
                // }
                TransactionData::WithdrawFromTreasury { recipient, amount, approvals } => {
                    info!("TREASURY: Memproses permintaan penarikan sebesar {} ke alamat {}", amount, hex::encode(recipient.as_ref()));

                    // 1. Definisikan pesan yang seharusnya ditandatangani oleh para pengembang.
                    // Pesan ini harus konsisten dengan yang digunakan oleh para dev saat membuat tanda tangan.
                    let mut message_to_sign = Vec::new();
                    message_to_sign.extend_from_slice(recipient.as_ref());
                    message_to_sign.extend_from_slice(&amount.to_be_bytes());
                    let message_hash = sha2::Sha256::digest(&message_to_sign);

                    // 2. Tentukan ambang batas persetujuan (misalnya > 50%)
                    let required_approvals = (DEVELOPER_COMMITTEE.len() / 2) + 1;
                    let mut valid_approvers = HashSet::new();

                    // 3. Muat daftar alamat komite dari konstanta
                    let committee_addresses: HashSet<Address> = DEVELOPER_COMMITTEE.iter()
                        .map(|hex_str| {
                            let clean_hex = hex_str.trim_start_matches("0x");
                            let bytes = hex::decode(clean_hex).expect("Invalid hex in DEVELOPER_COMMITTEE");
                            Address(bytes.try_into().expect("Invalid address length in DEVELOPER_COMMITTEE"))
                        })
                        .collect();

                    // 4. VERIFIKASI SETIAP TANDA TANGAN (BAGIAN PALING PENTING)
                    for signature in approvals {
                        // Cari siapa pemilik tanda tangan ini di antara anggota komite
                        for dev_address in &committee_addresses {
                            if crypto::verify(dev_address.as_ref(), &message_hash, signature) {
                                // Tanda tangan valid dan berasal dari anggota komite.
                                // Masukkan ke set untuk memastikan setiap dev hanya dihitung sekali.
                                valid_approvers.insert(*dev_address);
                                break; // Lanjut ke tanda tangan berikutnya, tidak perlu cek dev lain untuk sig ini.
                            }
                        }
                    }

                    // 5. Periksa apakah ambang batas tercapai
                    if valid_approvers.len() >= required_approvals {
                        info!("TREASURY: Persetujuan valid tercapai ({} dari {} dibutuhkan). Melakukan transfer.", valid_approvers.len(), required_approvals);
                        
                        // Lakukan transfer dari akun treasury ke penerima
                        let treasury_hashed_key = KeccakHasher::hash(TREASURY_ADDRESS.as_ref());
                        let mut treasury_account: Account = trie.get(&treasury_hashed_key)?
                            .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
                            .ok_or(BlockchainError::LogicError("Akun treasury tidak ditemukan.".into()))?;

                        if treasury_account.balance < *amount {
                            return Err(BlockchainError::InsufficientBalance { has: treasury_account.balance, needs: *amount });
                        }
                        treasury_account.balance -= *amount;

                        let recipient_hashed_key = KeccakHasher::hash(recipient.as_ref());
                        let mut recipient_account: Account = trie.get(&recipient_hashed_key)?
                            .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
                            .unwrap_or_default();
                        recipient_account.balance += *amount;

                        trie.insert(&treasury_hashed_key, &bincode::serialize(&treasury_account)?)?;
                        trie.insert(&recipient_hashed_key, &bincode::serialize(&recipient_account)?)?;

                    } else {
                        warn!("TREASURY: Permintaan penarikan ditolak. Persetujuan tidak cukup (hanya {} dari {}).", valid_approvers.len(), required_approvals);
                        // Kembalikan error agar transaksi ini dianggap tidak valid dan ditolak dari blok.
                        return Err(BlockchainError::TransactionInvalid("Persetujuan dari komite pengembang tidak mencukupi.".into()));
                    }
                }
                TransactionData::DeployContract { code } => {
                    if code.is_empty() {
                        return Err(BlockchainError::TransactionInvalid("Kode kontrak tidak boleh kosong.".into()));
                    }
                    let contract_address_bytes = {
                        let mut data = Vec::new();
                        data.extend_from_slice(tx.sender.as_ref());
                        data.extend_from_slice(&sender_account.nonce.to_be_bytes());
                        KeccakHasher::hash(&data)
                    };
                    let contract_address = Address(contract_address_bytes.as_slice()[..ADDRESS_SIZE].try_into().unwrap());
                    let contract_hashed_key = KeccakHasher::hash(contract_address.as_ref());

                    // Buat trie penyimpanan kosong untuk kontrak baru
                    let empty_storage_session = self.state.create_trie_session(Default::default(), COL_CONTRACT_STORAGE);
                    let initial_storage_root = empty_storage_session.commit()?;

                    let code_hash = KeccakHasher::hash(code).to_vec();
                    let contract_account = Account {
                        code_hash: Some(code_hash.clone()),
                        storage_root: Some(initial_storage_root.to_vec()),
                        ..Default::default()
                    };
                    
                    // Tambahkan operasi DB untuk menyimpan kode mentah
                    db_ops.push((COL_CONTRACT_CODE, code_hash, Some(code.clone())));
                    
                    trie.insert(&contract_hashed_key, &bincode::serialize(&contract_account)?)?;
                    info!("KONTRAK: Berhasil deploy di alamat {}", hex::encode(contract_address.as_ref()));
                }
                TransactionData::CallContract { contract_address, call_data } => {
                    let contract_hashed_key = KeccakHasher::hash(contract_address.as_ref());
                    let mut contract_account: Account = trie.get(&contract_hashed_key)?
                        .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
                        .ok_or_else(|| BlockchainError::TransactionInvalid("Akun kontrak tidak ditemukan".into()))?;

                    let code_hash = contract_account.code_hash.clone()
                        .ok_or_else(|| BlockchainError::TransactionInvalid("Akun bukan sebuah kontrak.".into()))?;
                    
                    let code = self.state.db.get(COL_CONTRACT_CODE, &code_hash)?
                         .ok_or_else(|| BlockchainError::TransactionInvalid("Kode kontrak tidak ditemukan di DB".into()))?;

                    // Tentukan gas limit untuk eksekusi
                    let gas_limit = 50_000_000; // Contoh, bisa dibuat lebih dinamis

                    let result = wasm_runtime::execute_contract(
                        &self.state,
                        &code,
                        contract_account.storage_root.clone(),
                        tx.sender, // Caller
                        call_data,
                        gas_limit,
                        block.header.timestamp as u64, // Kirim timestamp
                    )?;
                    
                    info!("KONTRAK: Panggilan ke {} berhasil. Gas terpakai: {}", hex::encode(contract_address.as_ref()), result.gas_used);

                    // Perbarui storage root kontrak dan simpan kembali akunnya
                    contract_account.storage_root = Some(result.new_storage_root);

                    if !result.requested_transfers.is_empty() {
                        info!("KONTRAK: Memproses {} permintaan transfer.", result.requested_transfers.len());
                        for (recipient, amount) in result.requested_transfers {
                            // Kurangi saldo dari akun kontrak
                            if contract_account.balance < amount {
                                // Ini seharusnya tidak terjadi jika kontrak ditulis dengan benar,
                                // tetapi ini adalah pengaman penting di level L1.
                                return Err(BlockchainError::LogicError(
                                    "Kontrak mencoba mentransfer lebih banyak dari saldonya.".into()
                                ));
                            }
                            contract_account.balance -= amount;

                            // Tambahkan saldo ke akun penerima
                            let recipient_hashed_key = KeccakHasher::hash(recipient.as_ref());
                            let mut recipient_account: Account = trie.get(&recipient_hashed_key)?
                                .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
                                .unwrap_or_default();
                            recipient_account.balance += amount;
                            trie.insert(&recipient_hashed_key, &bincode::serialize(&recipient_account)?)?;
                        }
                    }

                    trie.insert(&contract_hashed_key, &bincode::serialize(&contract_account)?)?;
                }
            }

            trie.insert(&sender_hashed_key, &bincode::serialize(&sender_account)?)?;
        }

        const BLOCK_REWARD: u64 = 1_000_000;
        const TREASURY_ALLOCATION_PERCENT: u64 = 10; // 10%

        let treasury_reward = (BLOCK_REWARD * TREASURY_ALLOCATION_PERCENT) / 100;
        let proposer_reward = BLOCK_REWARD - treasury_reward;

        // Tambahkan alokasi ke akun treasury
        let treasury_hashed_key = KeccakHasher::hash(TREASURY_ADDRESS.as_ref());
        let mut treasury_account: Account = trie.get(&treasury_hashed_key)?
            .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
            .unwrap_or_default();
        
        treasury_account.balance = treasury_account.balance.saturating_add(treasury_reward);
        trie.insert(&treasury_hashed_key, &bincode::serialize(&treasury_account)?)?;
        info!("TOKENOMICS: {} dialokasikan ke treasury.", treasury_reward);

        // ambahkan sisa imbalan + semua tip ke proposer
        let proposer_address = block.header.authority;
        let proposer_hashed_key = KeccakHasher::hash(proposer_address.as_ref());
        let mut proposer_account: Account = trie.get(&proposer_hashed_key)?
            .map(|d| bincode::deserialize(&d[..]).unwrap_or_default())
            .unwrap_or_default();

        proposer_account.balance = proposer_account.balance.saturating_add(proposer_reward + total_priority_fees);
        trie.insert(&proposer_hashed_key, &bincode::serialize(&proposer_account)?)?;
        info!("TOKENOMICS: Proposer {} menerima imbalan {} + tip {}.", hex::encode(proposer_address.as_ref()), proposer_reward, total_priority_fees);
        
        // Fee burning: `total_base_fees_to_burn` tidak ditambahkan ke akun mana pun, sehingga efektif hilang dari sirkulasi.
        info!("TOKENOMICS: Total base fee sebesar {} dibakar (dihapus dari sirkulasi).", total_base_fees_to_burn);
        
        // Dapatkan state root baru dari `trie` sebelum kita melepaskannya.
        let new_root = *trie.root();

        // Verifikasi Final sebelum Commit
        if new_root.as_ref() != block.header.state_root {
            error!("FATAL COMMIT ERROR: State root yang dihitung ({}) tidak cocok dengan state root di header ({}).", hex::encode(new_root.as_ref()), hex::encode(&block.header.state_root));
            return Err(BlockchainError::StateRootMismatch {
                expected: hex::encode(&block.header.state_root),
                got: hex::encode(new_root.as_ref()),
            });
        }

        // Secara eksplisit lepaskan pinjaman yang dipegang oleh `trie`. Setelah baris ini, `trie` tidak bisa digunakan lagi, dan `trie_db` bebas.
        drop(trie);

        // Sekarang `trie_db` bebas, kita bisa meminjamnya lagi untuk commit.
        trie_db.commit_pending()?;

        // Perbarui state in-memory terlebih dahulu
        self.state.state_root = new_root;
        // Gunakan nilai `current_l2_state_root` yang mungkin telah diubah oleh batch
        self.state.l2_state_root = current_l2_state_root.clone(); 
        
        if self.state.l2_state_root_history.front() != Some(&self.state.l2_state_root) {
            self.state.l2_state_root_history.push_front(self.state.l2_state_root.clone());
            if self.state.l2_state_root_history.len() > 256 {
                self.state.l2_state_root_history.pop_back();
            }
        }

        let mut final_ops = governance_ops; 
        final_ops.extend(l2_batch_ops);
        final_ops.extend(db_ops);

        // Perbarui state validator di memori dan siapkan untuk disimpan ke DB.
        for jailed_validator in validators_to_jail {
            self.state.validators.remove(&jailed_validator);
            self.state.jailed_validators.insert(jailed_validator);
        }

        // Simpan state sequencer baru ke DB
        final_ops.push((
            COL_METADATA,
            ACTIVE_SEQUENCERS_KEY.to_vec(),
            Some(bincode::serialize(&self.state.active_sequencers)?),
        ));
        
        final_ops.push((
            COL_METADATA,
            STATE_ROOT_KEY.to_vec(),
            Some(new_root.as_ref().to_vec()),
        ));
        final_ops.push((
            COL_BLOCKS,
            block.header.index.to_be_bytes().to_vec(),
            Some(bincode::serialize(&block).unwrap()),
        ));
        final_ops.push((
            COL_METADATA,
            L2_STATE_ROOT_KEY.to_vec(),
            // Simpan nilai `current_l2_state_root` yang sudah diperbarui ke DB
            Some(current_l2_state_root), 
        ));
        final_ops.push((
            COL_METADATA,
            b"l2_state_root_history".to_vec(),
            Some(bincode::serialize(&self.state.l2_state_root_history)?),
        ));
        final_ops.push((
            COL_METADATA,
            VALIDATORS_KEY.to_vec(),
            Some(bincode::serialize(&self.state.validators)?),
        ));
        final_ops.push((
            COL_STATE_JOURNAL,
            block.header.index.to_be_bytes().to_vec(),
            Some(new_root.as_ref().to_vec()),
        ));
        final_ops.push((
            COL_METADATA,
            b"latest_block_num".to_vec(),
            Some(block.header.index.to_be_bytes().to_vec()),
        ));
                
        self.state.db.commit(final_ops)?;

        let transactions = block.transactions.clone();
        self.block_hash_cache.insert(block.header.calculate_hash(), block.clone());
        self.chain.push(block);  
        
        Ok(transactions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ValidatorKeys;
    use tempfile::tempdir;

    // Helper untuk membuat transaksi dengan format baru
    fn create_test_tx(keys: &KeyPair, nonce: u64, data: TransactionData) -> Transaction {
        let mut tx = Transaction {
            sender: Address(keys.public_key_bytes()),
            data,
            nonce,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            signature: [0; SIGNATURE_SIZE],
        };
        let hash = tx.message_hash();
        tx.signature = keys.sign(&hash);
        tx
    }

    #[test]
    fn test_add_valid_block() {
        let dir = tempdir().unwrap();
        let mut blockchain = Blockchain::new(dir.path().to_str().unwrap()).unwrap();
        
        let authority_keys = ValidatorKeys::new();
        let authority_address = Address(authority_keys.signing_keys.public_key_bytes());
        
        // Siapkan state untuk authority & user
        let mut temp_state = HashMap::new();
        let authority_account = Account { balance: 1000, staked_amount: MINIMUM_STAKE, nonce: 0, vrf_public_key: authority_keys.vrf_keys.public.to_bytes() };
        temp_state.insert(authority_address, authority_account);
        blockchain.state.validators.insert(authority_address);
        
        let user1_keys = KeyPair::new();
        let user1_address = Address(user1_keys.public_key_bytes());
        let user1_account = Account { balance: 1000, nonce: 0, staked_amount: 0, vrf_public_key: [0; 32] };
        temp_state.insert(user1_address, user1_account);

        // Buat Genesis Block (Blok #0) secara manual
        let timestamp = 1;
        let genesis_block = blockchain.create_block(&authority_keys.signing_keys, vec![], vec![], vec![], timestamp);
        let genesis_result = blockchain.add_block(genesis_block);
        assert!(genesis_result.is_ok());
        assert_eq!(blockchain.chain.len(), 1);

        // Sekarang, buat Blok #1 dengan transaksi
        let tx = create_test_tx(&user1_keys, 0, TransactionData::Transfer { recipient: authority_address, amount: 100 });
        
        let timestamp = 2;
        let last_header = blockchain.chain.last().unwrap().header.clone();
        let mut transcript = merlin::Transcript::new(b"EVICE_VRF_PROPOSER_ELECTION");
        transcript.append_message(b"last_block_hash", &last_header.calculate_hash());
        transcript.append_message(b"timestamp", &timestamp.to_be_bytes());
        let (in_out, proof, _) = authority_keys.vrf_keys.vrf_sign(transcript);
        
        let block = blockchain.create_block(
            &authority_keys.signing_keys, 
            vec![tx], 
            in_out.to_preout().to_bytes().to_vec(), 
            proof.to_bytes().to_vec(),
            timestamp
        );

        let result = blockchain.add_block(block);
        
        assert!(result.is_ok());
        assert_eq!(blockchain.chain.len(), 2);
    }
}

