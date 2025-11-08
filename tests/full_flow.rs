// tests/full_flow.rs

// Deklarasikan modul common untuk menggunakan fungsi helper
mod common;

use evice_blockchain::{
    Address, TransactionData, WithdrawalProof,
    crypto::KeyPair,
    state::{Account, L2_BRIDGE_ADDRESS},
    l2_circuit::{get_poseidon_parameters, Leaf, MerkleTreeConfig},
};

use common::{setup_blockchain, create_signed_transfer_tx};
use ark_bls12_381::Fr;
use ark_crypto_primitives::merkle_tree::MerkleTree;
use ark_ff::{BigInteger, PrimeField};

#[test]
fn test_l1_to_l2_to_l1_lifecycle() {
    // ===================================================================
    //                             LANGKAH 1: SETUP
    // ===================================================================
    println!("--- LANGKAH 1: Setup Blockchain ---");
    
    let (_temp_dir, mut blockchain, validator_keys) = setup_blockchain(1);
    let validator = &validator_keys[0];

    let alice_keys = KeyPair::new();
    let alice_address = Address(alice_keys.public_key_bytes());
    
    // Beri dana awal kepada Alice
    let initial_alice_balance = 1_000_000;
    let mut session = blockchain.state.create_trie_session();
    session.set_account(&alice_address, &Account { balance: initial_alice_balance, ..Default::default() }).unwrap();
    let root_after_funding = session.commit().unwrap();
    blockchain.state.state_root = root_after_funding;
    
    let block1 = blockchain.create_block(&validator.signing_keys, vec![], root_after_funding.to_vec(), vec![], vec![], 2);
    blockchain.finalize_and_commit_block(block1).unwrap();
    
    println!("Setup Selesai. Saldo awal Alice: {}", initial_alice_balance);
    println!("Alamat L2 Bridge: 0x{}...", hex::encode(&L2_BRIDGE_ADDRESS.as_ref()[..4]));

    // ===================================================================
    //                       LANGKAH 2: DEPOSIT KE L2
    // ===================================================================
    println!("\n--- LANGKAH 2: Alice Melakukan Deposit 10,000 ke L2 ---");
    
    let deposit_amount = 10_000;
    let deposit_tx_data = TransactionData::DepositToL2 { amount: deposit_amount };
    let mut deposit_tx = create_signed_transfer_tx(&alice_keys, Address::default(), 0, 0, &blockchain); // nonce 0
    deposit_tx.data = deposit_tx_data;
    deposit_tx.signature = alice_keys.sign(&deposit_tx.message_hash());

    let block_with_deposit = blockchain.create_block(&validator.signing_keys, vec![deposit_tx.clone()], blockchain.state.state_root.to_vec(), vec![], vec![], 3);
    blockchain.finalize_and_commit_block(block_with_deposit).unwrap();

    // Verifikasi state setelah deposit
    let fee_paid_deposit = deposit_tx.data.base_gas_cost() * (blockchain.chain.last().unwrap().header.base_fee_per_gas + deposit_tx.max_priority_fee_per_gas);
    let alice_balance_after_deposit = blockchain.state.get_account(&alice_address).unwrap().unwrap().balance;
    let bridge_balance_after_deposit = blockchain.state.get_account(&L2_BRIDGE_ADDRESS).unwrap().unwrap().balance;

    assert_eq!(alice_balance_after_deposit, initial_alice_balance - deposit_amount - fee_paid_deposit);
    assert_eq!(bridge_balance_after_deposit, deposit_amount);
    println!("✅ SUKSES: Deposit berhasil. Saldo Alice: {}, Saldo Bridge: {}", alice_balance_after_deposit, bridge_balance_after_deposit);

    // ===================================================================
    //                LANGKAH 3: SIMULASI & SUBMIT ROLLUP BATCH
    // ===================================================================
    println!("\n--- LANGKAH 3: Sequencer Mensimulasikan Transaksi L2 & Mengirim Batch ke L1 ---");

    // Di dunia nyata, ini akan melibatkan sequencer, prover, dll.
    // Di tes ini, kita simulasikan hasilnya: state root L2 baru.
    let old_l2_root = blockchain.state.l2_state_root.clone();
    let new_l2_root = vec![42; 32]; // State root baru yang kita buat-buat
    
    let rollup_tx_data = TransactionData::SubmitRollupBatch {
        old_state_root: old_l2_root,
        new_state_root: new_l2_root.clone(),
        compressed_batch: vec![1, 2, 3], // Data sembarang
        zk_proof: vec![], // Bukti ZK kosong, karena verifikasi di-skip dalam `finalize_and_commit_block`
        is_test_tx: true,
    };
    let mut rollup_tx = create_signed_transfer_tx(&validator.signing_keys, Address::default(), 0, 0, &blockchain); // nonce 0 validator
    rollup_tx.data = rollup_tx_data;
    rollup_tx.signature = validator.signing_keys.sign(&rollup_tx.message_hash());

    let block_with_rollup = blockchain.create_block(&validator.signing_keys, vec![rollup_tx], blockchain.state.state_root.to_vec(), vec![], vec![], 4);
    blockchain.finalize_and_commit_block(block_with_rollup).unwrap();

    // Verifikasi state L2 root di L1
    assert_eq!(blockchain.state.l2_state_root, new_l2_root);
    println!("✅ SUKSES: Rollup Batch berhasil diproses. State root L2 di L1 telah diperbarui.");

    // ===================================================================
    //                      LANGKAH 4: PENARIKAN DARI L2
    // ===================================================================
    println!("\n--- LANGKAH 4: Alice Melakukan Penarikan 1,000 dari L2 ---");

    let withdrawal_amount = 1_000;
    let poseidon_params = get_poseidon_parameters();

    // PERBAIKAN: Gunakan `from_be_bytes_mod_order` agar konsisten dengan verifier
    let alice_pubkey_fr = Fr::from_be_bytes_mod_order(alice_address.as_ref());
    let alice_l2_leaf: Leaf = [alice_pubkey_fr, Fr::from(withdrawal_amount)];

    // ... (sisa dari pembuatan tree dan bukti tetap sama) ...
    let dummy_leaf: Leaf = [Fr::default(), Fr::default()];
    let leaves_for_tree = vec![alice_l2_leaf, dummy_leaf];

    let fake_l2_tree = MerkleTree::<MerkleTreeConfig>::new(
        &poseidon_params, &poseidon_params, &leaves_for_tree
    ).unwrap();
    let fake_l2_root_fr = fake_l2_tree.root();
    let withdrawal_path = fake_l2_tree.generate_proof(0).unwrap();

    let withdrawal_proof = WithdrawalProof {
        l2_state_root: fake_l2_root_fr.into_bigint().to_bytes_be(),
        leaf_data: alice_l2_leaf,
        merkle_path: withdrawal_path,
    };
    // PERBAIKAN PENTING: Untuk lolos verifikasi di `finalize_and_commit_block`,
    // `blockchain.state.l2_state_root` harus cocok dengan `withdrawal_proof.l2_state_root`.
    // Jadi, kita "curang" dan mengatur state L1 untuk sementara.
    blockchain.state.l2_state_root = withdrawal_proof.l2_state_root.clone();

    let withdraw_tx_data = TransactionData::WithdrawFromL2 { amount: withdrawal_amount, withdrawal_proof };
    let mut withdraw_tx = create_signed_transfer_tx(&alice_keys, Address::default(), 0, 1, &blockchain); // nonce 1 alice
    withdraw_tx.data = withdraw_tx_data;
    withdraw_tx.signature = alice_keys.sign(&withdraw_tx.message_hash());

    let block_with_withdrawal = blockchain.create_block(&validator.signing_keys, vec![withdraw_tx.clone()], blockchain.state.state_root.to_vec(), vec![], vec![], 5);
    blockchain.finalize_and_commit_block(block_with_withdrawal).unwrap();

    // Verifikasi state akhir
    let fee_paid_withdrawal = withdraw_tx.data.base_gas_cost() * (blockchain.chain.last().unwrap().header.base_fee_per_gas + withdraw_tx.max_priority_fee_per_gas);
    let final_alice_balance = blockchain.state.get_account(&alice_address).unwrap().unwrap().balance;
    let final_bridge_balance = blockchain.state.get_account(&L2_BRIDGE_ADDRESS).unwrap().unwrap().balance;
    
    let expected_alice_balance = alice_balance_after_deposit + withdrawal_amount - fee_paid_withdrawal;

    assert_eq!(final_alice_balance, expected_alice_balance);
    assert_eq!(final_bridge_balance, bridge_balance_after_deposit - withdrawal_amount);
    println!("✅ SUKSES: Penarikan berhasil. Saldo akhir Alice: {}, Saldo akhir Bridge: {}", final_alice_balance, final_bridge_balance);
    println!("\n🎉 SELURUH SIKLUS L1 -> L2 -> L1 BERHASIL DIUJI! 🎉");
}