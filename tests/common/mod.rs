// File: tests/common/mod.rs

use evice_blockchain::{
    blockchain::Blockchain,
    crypto::{KeyPair, ValidatorKeys},
    Address, Transaction, TransactionData,
    crypto::SIGNATURE_SIZE,
    l2_circuit::{TransferCircuit, get_poseidon_parameters} 
};

use tempfile::TempDir;
use std::fs::File;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;

// Fungsi untuk setup blockchain baru di direktori sementara untuk setiap tes
pub fn setup_blockchain(num_validators: usize) -> (TempDir, Blockchain, Vec<ValidatorKeys>) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("db");
    
    // ===================================================================
    // PERBAIKAN: Buat file vk.bin yang valid secara dinamis
    // ===================================================================
    let vk_path = temp_dir.path().join("verifying_key.bin");
    {
        let poseidon_params = get_poseidon_parameters();

        let dummy_circuit = TransferCircuit {
            old_merkle_root: Fr::default(),
            new_merkle_root: Fr::default(),
            amount: Fr::default(),
            sender_leaf: [Fr::default(); 2],
            sender_path: Default::default(),
            recipient_leaf: [Fr::default(); 2],
            recipient_path: Default::default(),
            // Gunakan parameter yang valid, bukan Default::default()
            leaf_crh_params: poseidon_params.clone(),
            two_to_one_crh_params: poseidon_params,
        };

        let mut rng = thread_rng();
        let (_, vk) = Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit, &mut rng)
            .expect("Gagal membuat setup sirkuit");

        let mut vk_file = File::create(&vk_path).unwrap();
        vk.serialize_uncompressed(&mut vk_file).unwrap();
    }

    // ===================================================================
    // PERBAIKAN: Buat Blockchain DULU, lalu bootstrap StateMachine-nya
    // ===================================================================
    
    // 1. Buat instance Blockchain. Ini akan membuat StateMachine internal
    //    dan mengunci file database.
    let mut blockchain = Blockchain::new(db_path.to_str().unwrap(), vk_path.to_str().unwrap())
        .expect("Failed to create blockchain with bootstrapped state");

    // 2. Panggil fungsi bootstrap pada StateMachine YANG SUDAH ADA di dalam blockchain.
    let validator_keys = blockchain.state.bootstrap_genesis_state(num_validators).unwrap();

    // 3. Buat dan simpan genesis block. State di DB sudah benar dari bootstrap.
    //    Kita hanya perlu memperbarui state in-memory (chain).
    let genesis_block = blockchain.create_block(
        &validator_keys[0].signing_keys, vec![], blockchain.state.state_root.to_vec(), vec![], vec![], 1
    );
    
    use evice_blockchain::state::COL_BLOCKS;
    let genesis_op = (
        COL_BLOCKS,
        0u64.to_be_bytes().to_vec(),
        Some(bincode::serialize(&genesis_block).unwrap())
    );
    blockchain.state.db.commit(vec![genesis_op]).unwrap();
    blockchain.chain.push(genesis_block);

    (temp_dir, blockchain, validator_keys)
}

pub fn create_signed_transfer_tx(
    sender_keys: &KeyPair,
    recipient: Address,
    amount: u64,
    nonce: u64,
    blockchain: &Blockchain,
) -> Transaction {
    let last_block = blockchain.chain.last().unwrap();
    let base_fee = last_block.header.base_fee_per_gas;

    let data = TransactionData::Transfer { recipient, amount };
    let mut tx = Transaction {
        sender: Address(sender_keys.public_key_bytes()),
        data,
        nonce,
        max_fee_per_gas: base_fee + 2,
        max_priority_fee_per_gas: 2,
        signature: [0; SIGNATURE_SIZE],
    };
    let hash = tx.message_hash();
    tx.signature = sender_keys.sign(&hash);
    tx
}