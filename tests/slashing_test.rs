// tests/slashing_test.rs

mod common;

use evice_blockchain::{
    blockchain::{BlockHeader, DoubleSignEvidence},
    crypto::KeyPair,
    state::Account,
    Address, TransactionData,
};
use common::{setup_blockchain, create_signed_transfer_tx};

#[test]
fn test_double_signing_slashing_and_reward() {
    // --- 1. SETUP ---
    println!("--- LANGKAH 1: Setup Blockchain ---");
    let (_temp_dir, mut blockchain, validator_keys) = setup_blockchain(3);
    
    let v_honest_proposer = &validator_keys[0];
    let v_malicious = &validator_keys[1];
    // PERBAIKAN: Hapus variabel yang tidak terpakai
    // let v_honest_other = &validator_keys[2]; 

    let reporter_keys = KeyPair::new();
    let reporter_address = Address(reporter_keys.public_key_bytes());

    let mut setup_session = blockchain.state.create_trie_session();
    let reporter_account = Account { balance: 1000, ..Default::default() };
    setup_session.set_account(&reporter_address, &reporter_account).unwrap();
    let new_root = setup_session.commit().unwrap();
    blockchain.state.state_root = new_root;
    println!("Validator jahat: 0x{}...", hex::encode(&v_malicious.signing_keys.public_key_bytes()[..4]));
    println!("Pelapor: 0x{}...", hex::encode(&reporter_address.as_ref()[..4]));

    // --- 2. BUAT BUKTI KECURANGAN ---
    println!("\n--- LANGKAH 2: Membuat Bukti Double Signing ---");
    let parent_block = blockchain.chain.last().unwrap();
    let target_index = parent_block.header.index + 1;
    let prev_hash = parent_block.header.calculate_hash();

    let mut header1 = BlockHeader {
        index: target_index,
        timestamp: 10,
        prev_hash: prev_hash.clone(),
        state_root: vec![1; 32], // State root berbeda
        transactions_root: vec![1; 32],
        authority: Address(v_malicious.signing_keys.public_key_bytes()),
        gas_used: 100,
        base_fee_per_gas: 10,
        signature: [0; evice_blockchain::crypto::SIGNATURE_SIZE],
    };
    header1.signature = v_malicious.signing_keys.sign(&header1.message_to_sign());

    let mut header2 = BlockHeader {
        index: target_index,
        timestamp: 11, // Timestamp berbeda
        prev_hash,
        state_root: vec![2; 32], // State root berbeda
        transactions_root: vec![2; 32],
        authority: Address(v_malicious.signing_keys.public_key_bytes()),
        gas_used: 100,
        base_fee_per_gas: 10,
        signature: [0; evice_blockchain::crypto::SIGNATURE_SIZE],
    };
    header2.signature = v_malicious.signing_keys.sign(&header2.message_to_sign());
    let evidence = DoubleSignEvidence { header1, header2 };
    println!("Bukti berhasil dibuat untuk blok #{}", target_index);

    // --- 3. KIRIM LAPORAN ---
    println!("\n--- LANGKAH 3: Pelapor Mengirim Transaksi Laporan ---");
    let report_tx_data = TransactionData::ReportDoubleSigning { evidence };
    let mut report_tx = create_signed_transfer_tx(&reporter_keys, Address::default(), 0, 0, &blockchain);
    report_tx.data = report_tx_data;
    report_tx.signature = reporter_keys.sign(&report_tx.message_hash());

    // --- 4. PROSES BLOK & SIMPAN STATE AWAL ---
    println!("\n--- LANGKAH 4: Validator Jujur Membuat Blok Laporan ---");
    let block_with_report = blockchain.create_block(
        &v_honest_proposer.signing_keys, vec![report_tx.clone()], blockchain.state.state_root.to_vec(), vec![], vec![], 20
    );
    
    let malicious_addr = Address(v_malicious.signing_keys.public_key_bytes());
    let initial_malicious_stake = blockchain.state.get_account(&malicious_addr).unwrap().unwrap().staked_amount;
    let initial_reporter_balance = blockchain.state.get_account(&reporter_address).unwrap().unwrap().balance;
    println!("Stake awal pelaku: {}", initial_malicious_stake);
    println!("Saldo awal pelapor: {}", initial_reporter_balance);

    blockchain.finalize_and_commit_block(block_with_report).expect("Gagal memfinalisasi blok laporan");
    println!("Blok yang berisi laporan berhasil diproses.");

    // --- 5. VERIFIKASI HASIL ---
    println!("\n--- LANGKAH 5: Verifikasi Hasil Slashing & Imbalan ---");
    let final_malicious_account = blockchain.state.get_account(&malicious_addr).unwrap().unwrap();
    let final_reporter_account = blockchain.state.get_account(&reporter_address).unwrap().unwrap();

    // Verifikasi Hukuman
    let slash_amount = initial_malicious_stake / 10;
    let expected_malicious_stake = initial_malicious_stake - slash_amount;
    assert_eq!(final_malicious_account.staked_amount, expected_malicious_stake, "Stake pelaku salah");
    println!("✅ SUKSES: Stake pelaku di-slash menjadi {}.", final_malicious_account.staked_amount);

    // Verifikasi Imbalan
    // PERBAIKAN: Gunakan variabel `reward_amount` dan perhitungkan biaya transaksi
    let reward_amount = slash_amount / 2;
    let fee_paid = report_tx.data.base_gas_cost() * (blockchain.chain.last().unwrap().header.base_fee_per_gas + report_tx.max_priority_fee_per_gas);
    let expected_reporter_balance = initial_reporter_balance + reward_amount - fee_paid;
    assert_eq!(final_reporter_account.balance, expected_reporter_balance, "Saldo akhir pelapor salah");
    println!("✅ SUKSES: Saldo pelapor (setelah imbalan dan biaya) menjadi {}.", final_reporter_account.balance);
    
    // Verifikasi Nonce
    assert_eq!(final_reporter_account.nonce, 1, "Nonce pelapor seharusnya bertambah");
    println!("✅ SUKSES: Nonce pelapor diperbarui menjadi 1.");
}