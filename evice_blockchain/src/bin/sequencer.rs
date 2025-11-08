// src/bin/sequencer.rs

use evice_blockchain::{
    crypto::{KeyPair, ValidatorKeys, public_key_to_address, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE},
    keystore::Keystore,
    rpc_client::RpcClient,
    l2_circuit::{BatchTxInfo, BatchSystemCircuit, PoseidonMerkleTreeParams},
    crypto, serde_helpers, MerkleTreeConfig, Leaf, Transaction, TransactionData,
};

use std::time::Duration;
use tokio::time::interval;
use log::{info, error, warn};
use rpassword::read_password;
use clap::Parser;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::process::Command;
use std::fs::File;
use sha2::Digest;
use merlin::Transcript;
use schnorrkel::SecretKey as SchnorrkelSecretKey;

use ark_bls12_381::Fr;
use ark_crypto_primitives::{merkle_tree::MerkleTree};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ff::{PrimeField, BigInteger};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use actix_web::{post, web, App, error, HttpResponse, HttpServer, Responder};
use actix_web_ratelimit::{RateLimit, config::RateLimitConfig, store::MemoryStore};

const L2_CHAIN_ID: u64 = 77;

#[derive(Parser, Debug)]
#[clap(name = "sequencer-cli")]
struct Cli {
    #[clap(long, default_value = "http://127.0.0.1:8080")]
    l1_rpc_url: String,
    #[clap(long, default_value = "127.0.0.1:8081")]
    l2_listen_addr: String,
    #[clap(long)]
    keystore_path: String,
    #[clap(long)]
    vrf_private_key: String,
    #[clap(long, default_value = "./poseidon_params.bin")]
    params_path: String,
    #[clap(long, default_value = "./proving_key.bin")]
    proving_key_path: String,
    #[clap(long, help = "Pasangan kunci (public:private) anggota DAC dalam format hex, dipisahkan koma.",
    use_value_delimiter = true)]
    dac_keypairs: Vec<String>,
}

/// Representasi transaksi L2 yang diterima dari pengguna.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct L2Transaction {
    from: String, // Public key pengirim dalam format hex
    to: String,   // Public key penerima dalam format hex
    amount: u64,
    nonce: u64, // Nonce L2 penting untuk mencegah replay
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    signature: String, // Signature dalam format hex
}

impl L2Transaction {
    /// Membuat hash dari pesan L2 yang akan ditandatangani.
    fn message_hash(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&L2_CHAIN_ID.to_be_bytes());
        data.extend_from_slice(self.from.as_bytes());
        data.extend_from_slice(self.to.as_bytes());
        data.extend_from_slice(&self.amount.to_be_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.max_fee_per_gas.to_be_bytes());
        data.extend_from_slice(&self.max_priority_fee_per_gas.to_be_bytes());
        sha2::Sha256::digest(&data).to_vec()
    }
}

/// State dari Sequencer, dibagikan antar thread.
#[derive(Clone)]
struct SequencerState {
    l2_transactions: Arc<Mutex<Vec<L2Transaction>>>,
    l2_state: Arc<Mutex<L2State>>,
    poseidon_params: Arc<PoseidonMerkleTreeParams>,
}

/// State L2 yang dikelola oleh sequencer.
struct L2State {
    merkle_tree: MerkleTree<MerkleTreeConfig>,
    // Mapping dari public key (hex) ke index di dalam tree
    account_map: HashMap<String, usize>,
    leaves: Vec<Leaf>,
}

// Struct baru untuk serialisasi data sirkuit
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct CircuitData {
    old_merkle_root: Fr,
    new_merkle_root: Fr,
    amount: Fr,
    sender_leaf: [Fr; 2],
    sender_path: ark_crypto_primitives::merkle_tree::Path<MerkleTreeConfig>,
    recipient_leaf: [Fr; 2],
    recipient_path: ark_crypto_primitives::merkle_tree::Path<MerkleTreeConfig>,
}

// --- Handler RPC untuk Sequencer ---
#[post("/l2_sendTransaction")]
async fn l2_send_transaction(
    state: web::Data<SequencerState>,
    tx: web::Json<L2Transaction>,
) -> Result<impl Responder, error::Error> {
    let l2_tx = tx.into_inner();
    info!("L2_RPC: Menerima transaksi: dari {} ke {} sejumlah {}", l2_tx.from, l2_tx.to, l2_tx.amount);
    
    // --- Validasi tanda tangan L2 yang lebih tangguh ---
    let pub_key_bytes = hex::decode(&l2_tx.from)
        .map_err(|_| error::ErrorBadRequest("Format public key 'from' tidak valid."))?;

    let signature_bytes = hex::decode(&l2_tx.signature)
        .map_err(|_| error::ErrorBadRequest("Format signature tidak valid."))?;

    if !crypto::verify(&pub_key_bytes, &l2_tx.message_hash(), &signature_bytes) {
        warn!("L2_RPC: Tanda tangan transaksi L2 tidak valid!");
        return Err(error::ErrorUnauthorized("Tanda tangan tidak valid."));
    }

    // Mengunci mutex dengan penanganan error jika terjadi 'poisoned'
    let mut transactions_guard = state.l2_transactions.lock()
        .map_err(|_| error::ErrorInternalServerError("Gagal mengunci mempool L2."))?;
    transactions_guard.push(l2_tx);

    Ok(HttpResponse::Ok().json("Transaksi L2 diterima dan valid"))
}

#[serde_as]
#[derive(Serialize, Deserialize)]
struct MerkleProofResponse {
    #[serde_as(as = "serde_helpers::ArkFrArray<2>")]
    pub leaf_data: Leaf,
    #[serde_as(as = "serde_helpers::ArkPath")]
    pub merkle_path: ark_crypto_primitives::merkle_tree::Path<MerkleTreeConfig>,
}

#[post("/l2_getMerkleProof")]
async fn l2_get_merkle_proof(
    state: web::Data<SequencerState>,
    params: web::Json<(String, String)>,
) -> Result<impl Responder, error::Error> {
    let (address_hex, l2_root_hex) = params.into_inner();
    info!("L2_RPC: Permintaan bukti merkle untuk alamat {} pada root {}", address_hex, l2_root_hex);

    let l2_state = state.l2_state.lock().unwrap();

    let current_root_bytes = l2_state.merkle_tree.root().into_bigint().to_bytes_be();
    if hex::encode(&current_root_bytes) != l2_root_hex {
        return Err(error::ErrorBadRequest("State root L2 tidak cocok atau sudah usang."));
    }
    
    if let Some(index) = l2_state.account_map.get(&address_hex) {
        let leaf_data = l2_state.leaves[*index];
        let merkle_path = l2_state.merkle_tree.generate_proof(*index).map_err(|e| error::ErrorInternalServerError(format!("Gagal membuat bukti Merkle: {}", e)))?;

        Ok(HttpResponse::Ok().json(MerkleProofResponse {
            leaf_data,
            merkle_path,
        }))
    } else {
        Err(error::ErrorNotFound("Alamat tidak ditemukan di state L2."))
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();

    if cli.dac_keypairs.is_empty() {
        return Err("Diperlukan setidaknya satu pasangan kunci DAC (`--dac-keypairs`)".into());
    }
    let dac_keypairs: Vec<KeyPair> = cli.dac_keypairs.iter()
        .map(|kp_str| {
            let parts: Vec<&str> = kp_str.split(':').collect();
            if parts.len() != 2 {
                return Err("Format pasangan kunci DAC tidak valid. Gunakan 'publicKeyHex:privateKeyHex'".into());
            }
            let pk_hex = parts[0];
            let sk_hex = parts[1];

            let pk_bytes = hex::decode(pk_hex)
                .map_err(|e| format!("Kunci publik DAC tidak valid: {}", e))?;
            let sk_bytes = hex::decode(sk_hex)
                .map_err(|e| format!("Kunci privat DAC tidak valid: {}", e))?;

            if pk_bytes.len() != PUBLIC_KEY_SIZE || sk_bytes.len() != PRIVATE_KEY_SIZE {
                return Err(format!("Panjang kunci DAC tidak valid. Publik: {}/{}, Privat: {}/{}", pk_bytes.len(), PUBLIC_KEY_SIZE, sk_bytes.len(), PRIVATE_KEY_SIZE).into());
            }
            
            // Gunakan konstruktor yang sudah ada dan terverifikasi
            KeyPair::from_key_bytes(&pk_bytes, &sk_bytes)
                .map_err(|e| e.into())
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    info!("SEQUENCER: Berhasil memuat {} pasangan kunci anggota DAC.", dac_keypairs.len());

    // --- Setup Kunci Sequencer dengan benar (Signing + VRF) ---
    let keystore = Keystore::from_path(&cli.keystore_path)?;
    println!("🔒 Masukkan kata sandi untuk keystore sequencer '{}':", cli.keystore_path);
    let password = read_password()?;
    let private_key_bytes = keystore.decrypt(&password)?;
    let pub_key_bytes = hex::decode(&keystore.public_key)?; 
    
    let signing_keys = KeyPair::from_key_bytes(&pub_key_bytes, &private_key_bytes)?;
    let sequencer_address = public_key_to_address(&signing_keys.public_key_bytes());
    info!("SEQUENCER: Berjalan dengan alamat: 0x{}", hex::encode(sequencer_address.as_ref()));

    // Muat kunci VRF
    let vrf_secret_bytes = hex::decode(&cli.vrf_private_key)?;
    let vrf_secret = SchnorrkelSecretKey::from_ed25519_bytes(&vrf_secret_bytes)
        .map_err(|_| "Kunci privat VRF tidak valid. Pastikan panjangnya 64-byte.")?;
    let vrf_keys = vrf_secret.to_keypair();

    // Gabungkan menjadi ValidatorKeys
    let sequencer_keys = Arc::new(ValidatorKeys { signing_keys, vrf_keys });

    // --- Muat Parameter Kriptografi ---
    let params_file = File::open(&cli.params_path)?;
    let poseidon_params_loaded = Arc::new(PoseidonMerkleTreeParams::deserialize_uncompressed(params_file)?);

    // --- Inisialisasi State L2 ---
    let initial_leaves = vec![];
    let initial_tree = MerkleTree::<MerkleTreeConfig>::new(
        // PERBAIKAN: Gunakan variabel yang baru dimuat
        &poseidon_params_loaded.leaf_crh_params,
        &poseidon_params_loaded.two_to_one_crh_params,
        &initial_leaves,
    )?;

    let l2_state = Arc::new(Mutex::new(L2State {
        merkle_tree: initial_tree,
        account_map: HashMap::new(),
        leaves: initial_leaves,
    }));

    let sequencer_state = SequencerState {
        l2_transactions: Arc::new(Mutex::new(Vec::new())),
        l2_state,
        poseidon_params: poseidon_params_loaded, // Simpan Arc ke dalam state
    };
    
    // --- Jalankan Server RPC L2 di background ---
    let state_for_server = web::Data::new(sequencer_state.clone());
    let l2_listen_addr = cli.l2_listen_addr.clone();

    let store = Arc::new(MemoryStore::new());

    // Jalankan server di dalam task Tokio.
    tokio::spawn(async move {
        info!("SEQUENCER: Menjalankan server RPC L2 di http://{}", l2_listen_addr);
        
        HttpServer::new(move || {
            let config = RateLimitConfig::default()
                .max_requests(500) // Mungkin sequencer bisa handle lebih banyak request
                .window_secs(60);

            let ratelimiter = RateLimit::new(config, store.clone());

            // PERBAIKAN: Pastikan .wrap dipanggil pada App::new()
            App::new()
                .wrap(ratelimiter)
                .app_data(state_for_server.clone())
                .service(l2_send_transaction)
                .service(l2_get_merkle_proof)
        })
        .bind(&l2_listen_addr)
        .unwrap_or_else(|e| {
            panic!("Gagal melakukan bind ke alamat L2 {}: {}", l2_listen_addr, e);
        })
        .run()
        .await
    });

    // --- Loop Utama Sequencer ---
    info!("SEQUENCER: Loop utama dimulai, menunggu interval batch...");
    let mut l1_rpc_client = RpcClient::new(cli.l1_rpc_url, cli.l2_listen_addr.clone()).await?;
    let mut batch_interval = interval(Duration::from_secs(30));

    loop {
        batch_interval.tick().await;

        // 1. Lakukan pemilihan pemimpin
        let last_l1_block = l1_rpc_client.get_block_by_index(u64::MAX).await.unwrap(); // Sekarang akan berhasil
        let last_l1_hash = last_l1_block.header.calculate_hash();

        let mut transcript = Transcript::new(b"EVICE_L2_SEQUENCER_ELECTION");
        transcript.append_message(b"last_l1_hash", &last_l1_hash);
        
        // Gunakan method yang tersedia dari KeyPair untuk VRF
        let (vrf_in_out, vrf_proof, _) = sequencer_keys.vrf_keys.vrf_sign(transcript);
        let vrf_output_bytes: [u8; 32] = vrf_in_out.make_bytes(b"L2_SEQUENCER_VRF_CONTEXT");

        const SEQUENCER_THRESHOLD: u8 = 128;
        if vrf_output_bytes[0] > SEQUENCER_THRESHOLD {
            info!("SEQUENCER: Bukan giliran kita, output VRF terlalu tinggi.");
            continue;
        }
        info!("SEQUENCER: Terpilih sebagai pemimpin batch L2!");

        // 2. Kumpulkan transaksi untuk batch
        let l2_txs_to_process = {
            let mut txs = sequencer_state.l2_transactions.lock().unwrap();
            if txs.is_empty() {
                info!("SEQUENCER: Tidak ada transaksi L2 untuk diproses.");
                continue;
            }

            // --- INTI DARI FEE MARKET ---
            // Urutkan transaksi berdasarkan `max_priority_fee_per_gas` (tip)
            // dari yang tertinggi ke terendah.
            txs.sort_by(|a, b| b.max_priority_fee_per_gas.cmp(&a.max_priority_fee_per_gas));
            info!("SEQUENCER: Mengurutkan {} txs berdasarkan tip prioritas.", txs.len());
                
            // Ambil sejumlah transaksi teratas untuk dimasukkan ke dalam batch
            const BATCH_SIZE_LIMIT: usize = 100;
            let num_to_take = std::cmp::min(txs.len(), BATCH_SIZE_LIMIT);
            txs.drain(..num_to_take).collect::<Vec<_>>()
        };

        info!("SEQUENCER: Memproses {} transaksi L2 dengan prioritas tertinggi dalam satu batch.", l2_txs_to_process.len());

        // 3. Proses batch dan siapkan data untuk prover
        let (initial_root_fr, final_root_fr, circuit_input) = {
            let mut l2_state = sequencer_state.l2_state.lock().unwrap();
            let initial_root = l2_state.merkle_tree.root();
            
            let mut batch_tx_infos = Vec::new();
            let initial_leaves_clone = l2_state.leaves.clone();
            
            let mut current_tree = MerkleTree::<MerkleTreeConfig>::new(
                &sequencer_state.poseidon_params.leaf_crh_params,
                &sequencer_state.poseidon_params.two_to_one_crh_params,
                &l2_state.leaves,
            )?;

            for tx in &l2_txs_to_process {
                // Dapatkan atau buat akun & index
                let sender_pubkey_fr = Fr::from_le_bytes_mod_order(&hex::decode(&tx.from).unwrap());
                let recipient_pubkey_fr = Fr::from_le_bytes_mod_order(&hex::decode(&tx.to).unwrap());

                // --- Handle Sender ---
                let sender_idx = if let Some(idx) = l2_state.account_map.get(&tx.from) {
                    *idx
                } else {
                    let new_idx = l2_state.leaves.len();
                    l2_state.leaves.push([sender_pubkey_fr, Fr::from(1_000_000_u64)]);
                    l2_state.account_map.insert(tx.from.clone(), new_idx);
                    new_idx
                };

                // --- Handle Recipient ---
                let recipient_idx = if let Some(idx) = l2_state.account_map.get(&tx.to) {
                    *idx
                } else {
                    let new_idx = l2_state.leaves.len();
                    l2_state.leaves.push([recipient_pubkey_fr, Fr::from(0u64)]);
                    l2_state.account_map.insert(tx.to.clone(), new_idx);
                    new_idx
                };


                // Validasi saldo
                let amount_fr = Fr::from(tx.amount);
                if l2_state.leaves[sender_idx][1] < amount_fr {
                    warn!("SEQUENCER: Saldo tidak cukup untuk tx dari {}. Dilewati.", tx.from);
                    continue;
                }

                // Buat bukti terhadap state tree saat ini (sebelum diubah)
                let sender_path = current_tree.generate_proof(sender_idx)?;
                let recipient_path = current_tree.generate_proof(recipient_idx)?;

                // Tambahkan info ke batch untuk prover
                batch_tx_infos.push(BatchTxInfo {
                    amount: amount_fr,
                    sender_leaf_index: sender_idx as u32,
                    recipient_leaf_index: recipient_idx as u32,
                    sender_path,
                    recipient_path,
                });

                // Terapkan perubahan ke state lokal
                l2_state.leaves[sender_idx][1] -= amount_fr;
                l2_state.leaves[recipient_idx][1] += amount_fr;
                
                // Bangun ulang tree untuk transaksi berikutnya
                current_tree = MerkleTree::<MerkleTreeConfig>::new(
                    &sequencer_state.poseidon_params.leaf_crh_params,
                    &sequencer_state.poseidon_params.two_to_one_crh_params,
                    &l2_state.leaves,
                )?;
            }

            l2_state.merkle_tree = current_tree;
            let final_root = l2_state.merkle_tree.root();

            let circuit = BatchSystemCircuit {
                initial_root,
                final_root,
                transactions: batch_tx_infos,
                initial_leaves: initial_leaves_clone,
                leaf_crh_params: sequencer_state.poseidon_params.leaf_crh_params.clone(),
                two_to_one_crh_params: sequencer_state.poseidon_params.two_to_one_crh_params.clone(),
            };
            (initial_root, final_root, circuit)
        };

        // 4. Panggil Prover
        let mut circuit_data_bytes = Vec::new();
        circuit_input.serialize_uncompressed(&mut circuit_data_bytes)?;
        let circuit_data_hex = hex::encode(circuit_data_bytes);

        // Jalankan prover di thread yang memblokir
        let params = (cli.params_path.clone(), cli.proving_key_path.clone(), circuit_data_hex.clone());
        let prover_task = move || {
            info!("PROVER_TASK: Memulai pembuatan bukti ZK di thread terpisah...");
            Command::new("cargo")
                .args(&[
                    "run", "--bin", "prover", "--release", "--",
                    // PERHATIAN: Sesuaikan subcommand jika Anda mengubahnya di prover.rs
                    "--params-path", &params.0,
                    "--proving-key-path", &params.1,
                    "--circuit-data-hex", &params.2,
                ])
                .output()
        };

        // Jalankan dan tunggu hasilnya tanpa memblokir reactor utama
        let prover_output = match tokio::task::spawn_blocking(prover_task).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                error!("SEQUENCER: Prover task I/O error: {}", e);
                continue;
            },
            Err(e) => {
                error!("SEQUENCER: Gagal menjalankan prover task (panic?): {}", e);
                continue;
            }
        };
        
        if !prover_output.status.success() {
            error!("SEQUENCER: Prover gagal dengan stderr: {}", String::from_utf8_lossy(&prover_output.stderr));
            continue;
        }

        // --- Ekstrak bukti ZK dari output ---
        let proof_hex = String::from_utf8(prover_output.stdout)?.trim().to_string();
        if proof_hex.is_empty() {
            error!("SEQUENCER: Prover berhasil tetapi tidak menghasilkan output (proof).");
            continue;
        }

        let zk_proof = hex::decode(proof_hex)?;
        info!("SEQUENCER: Bukti ZK berhasil didapatkan dari prover.");

        // 5. Kirim Batch ke L1
        let nonce = l1_rpc_client.get_l1_account_info(sequencer_address).await?.nonce; // Sekarang akan berhasil
        let compressed_batch_data = bincode::serialize(&l2_txs_to_process)?;

        let batch_data_hash = sha2::Sha256::digest(&compressed_batch_data);
        let mut dac_signatures = Vec::new();

        // Tandatangani hash data batch dengan setiap KeyPair anggota DAC yang telah dimuat
        for keypair in &dac_keypairs {
            let signature = keypair.sign(&batch_data_hash);
            dac_signatures.push(signature);
        }
        
        info!("SEQUENCER: Berhasil mengumpulkan {} tanda tangan DAC yang berbeda untuk batch.", dac_signatures.len());

        let data = TransactionData::SubmitRollupBatch {
            old_state_root: initial_root_fr.into_bigint().to_bytes_be(),
            new_state_root: final_root_fr.into_bigint().to_bytes_be(),
            compressed_batch: compressed_batch_data,
            zk_proof,
            is_test_tx: false,
            vrf_output: vrf_in_out.to_preout().to_bytes().to_vec(),
            vrf_proof: vrf_proof.to_bytes().to_vec(),
            dac_signatures,
        };

        let mut tx = Transaction {
            sender: sequencer_address, data, nonce,
            max_fee_per_gas: 20, max_priority_fee_per_gas: 2,
            signature: [0; evice_blockchain::crypto::SIGNATURE_SIZE],
        };
        tx.signature = sequencer_keys.signing_keys.sign(&tx.message_hash());

        if let Err(e) = l1_rpc_client.submit_l1_transaction(&tx).await {
            error!("SEQUENCER: Gagal mengirim batch ke L1: {}", e);
        } else {
            info!("SEQUENCER: Batch berhasil dikirim ke L1 untuk finalisasi.");
        }
    }
}