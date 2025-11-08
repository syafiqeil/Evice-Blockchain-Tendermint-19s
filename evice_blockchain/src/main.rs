// src/main.rs

use clap::Parser;
use evice_blockchain::{
    blockchain::{Block, Blockchain, ChainMessage},
    consensus::{ConsensusMessage, Vote},
    crypto::{KeyPair, ValidatorKeys, public_key_to_address},
    genesis::{Genesis, GenesisAccount},
    keystore::Keystore,
    mempool::Mempool,
    p2p::{SyncRequest, SyncResponse},
    snapshot::{self, SnapshotMetadata},
    Address, p2p, rpc,
};
use log::{debug, error, info, warn};
use rpassword::read_password;
use schnorrkel::SecretKey as SchnorrkelSecretKey;
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{
    atomic::AtomicUsize,
    Arc, Mutex
};
use tokio::select;
use tokio::sync::{mpsc, broadcast};
use tokio::time::{interval, Duration, Instant};
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

const MAX_TRANSACTIONS_PER_BLOCK: usize = 10;
const SNAPSHOT_SYNC_THRESHOLD: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
enum ConsensusStep {
    Propose,
    Prevote,
    Precommit,
}

// Struct untuk state konsensus
struct ConsensusState {
    height: u64,
    round: u64,
    step: ConsensusStep,
    current_proposal: Option<Block>,
    prevotes: HashMap<Address, Vote>,
    precommits: HashMap<Address, Vote>,
    buffered_prevotes: HashMap<u64, Vec<Vote>>,
    buffered_proposals: HashMap<u64, Block>,
    proposer_schedule: Vec<Address>,
}

impl ConsensusState {
    fn new(height: u64, proposer_schedule: Vec<Address>) -> Self {
        info!("Memulai konsensus untuk height: {}", height);
        Self {
            height,
            round: 0,
            step: ConsensusStep::Propose,
            current_proposal: None,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            buffered_prevotes: HashMap::new(),
            buffered_proposals: HashMap::new(),
            proposer_schedule,
        }
    }

    fn reset_for_next_height(self, new_schedule: Vec<Address>) -> Self {
        let new_height = self.height + 1;
        let mut new_state = Self::new(new_height, new_schedule);
        new_state.buffered_prevotes = self.buffered_prevotes;
        new_state
    }
}

/// Menentukan urutan proposer yang acak namun deterministik untuk sebuah height.
/// Semua node yang jujur akan menghasilkan urutan yang sama persis.
fn determine_proposer_schedule(
    validators: &HashSet<Address>,
    chain: &Blockchain, // Kita butuh chain untuk mendapatkan hash blok terakhir
) -> Vec<Address> {
    if validators.is_empty() {
        return vec![];
    }

    let last_block_hash = chain.chain.last()
        .map_or(vec![0; 32], |b| b.header.calculate_hash());

    let mut ranked_validators = Vec::new();

    // Setiap validator menghasilkan output VRF-nya sendiri berdasarkan seed yang sama
    for validator_addr in validators {
        // Untuk tujuan penyusunan jadwal, kita tidak bisa mengetahui kunci privat VRF validator lain.
        // Jadi, kita akan menggunakan hash dari kunci publik mereka yang dikombinasikan dengan seed
        // sebagai sumber keacakan yang deterministik. Ini adalah pendekatan yang aman dan umum.
        let mut hasher = sha2::Sha256::new();
        hasher.update(&last_block_hash);
        hasher.update(validator_addr.as_ref());
        let rank_bytes = hasher.finalize();

        ranked_validators.push((rank_bytes, *validator_addr));
    }

    // Urutkan validator berdasarkan hasil hash mereka (dari terendah ke tertinggi)
    ranked_validators.sort_by(|a, b| a.0.cmp(&b.0));

    // Ekstrak hanya alamatnya untuk membuat jadwal final
    let schedule: Vec<Address> = ranked_validators.into_iter().map(|(_, addr)| addr).collect();
    
    debug!("[BFT] Jadwal proposer untuk height berikutnya ditentukan. Proposer ronde 0: 0x{}...", hex::encode(&schedule[0].as_ref()[..4]));

    schedule
}

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    #[clap(long)]
    bootstrap: bool,
    #[clap(long, default_value = "./database")]
    db_path: String,
    #[clap(long, default_value = "verifying_key.bin")]
    vk_path: String,
    #[clap(long)]
    bootstrap_node: Option<String>,
    #[clap(long, default_value = "8080")]
    rpc_port: u16,
    #[clap(long, default_value = "50000")]
    p2p_port: u16,
    #[clap(long)]
    is_authority: bool,
    #[clap(long, requires = "is_authority")]
    keystore_path: Option<String>,
    #[clap(long = "vrf-private-key", requires = "is_authority")]
    vrf_priv_key: Option<String>,
    #[clap(long, default_value = "./snapshots")]
    snapshot_path: String,
    #[clap(long, help = "Berikan kata sandi keystore secara langsung (untuk skrip pengujian).")]
    password: Option<String>,
}

#[derive(Debug)]
enum SyncState {
    Idle,
    DownloadingSnapshot {
        metadata: SnapshotMetadata,
        temp_file: File,
        next_chunk: u32,
    },
    SyncingBlocks,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    LogTracer::init()?;
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    if args.bootstrap {
        info!("Mem-bootstrap state awal dan menghasilkan genesis.json...");

        const NUM_VALIDATORS: usize = 6;
        const INITIAL_BALANCE: u128 = 1_000_000_000;
        const INITIAL_STAKE: u128 = 50_000_000;

        let mut validator_keys_generated: Vec<ValidatorKeys> = Vec::new();
        let mut genesis_accounts = HashMap::new();

        // 1. Buat akun untuk setiap validator
        for _ in 0..NUM_VALIDATORS {
            let keys = ValidatorKeys::new();
            let address_hex = hex::encode(keys.signing_keys.public_key_bytes());
            
            let account = GenesisAccount {
                balance: (INITIAL_BALANCE - INITIAL_STAKE).to_string(),
                staked_amount: INITIAL_STAKE.to_string(),
                vrf_public_key: Some(hex::encode(keys.vrf_keys.public.to_bytes())),
            };
            
            genesis_accounts.insert(address_hex, account);
            validator_keys_generated.push(keys);
        }
        
        // 2. Buat objek Genesis utama
        let genesis = Genesis {
            genesis_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            chain_id: "evice-testnet-v1".to_string(),
            accounts: genesis_accounts,
        };

        // 3. Tulis ke file genesis.json
        let genesis_json = serde_json::to_string_pretty(&genesis)?;
        let mut file = File::create("genesis.json")?;
        file.write_all(genesis_json.as_bytes())?;
        
        println!("\n✅ Berhasil membuat genesis.json!");
        
        // 4. Cetak kunci validator ke terminal agar bisa disalin oleh pengguna
        println!("\n========================================================================");
        println!("             KUNCI VALIDATOR GENESIS (SIMPAN INI BAIK-BAIK!)             ");
        println!("========================================================================");
        for (i, keys) in validator_keys_generated.iter().enumerate() {
            println!("\n--- Validator {} ---", i + 1);
            println!("Alamat (Sign PubKey): 0x{}", hex::encode(keys.signing_keys.public_key_bytes()));
            println!("Signing Private Key:  0x{}", hex::encode(keys.signing_keys.private_key_bytes()));
            println!("VRF Public Key:       0x{}", hex::encode(keys.vrf_keys.public.to_bytes()));
            println!("VRF Secret Key:       0x{}", hex::encode(keys.vrf_keys.secret.to_bytes()));
        }
        println!("\n========================================================================");

        info!("Bootstrap selesai. Program berhenti.");
        return Ok(());
    }

    let is_syncing = Arc::new(Mutex::new(false));

    let snapshot_dir = PathBuf::from(&args.snapshot_path);
    if !snapshot_dir.exists() {
        std::fs::create_dir_all(&snapshot_dir)?;
    }

    // Inisialisasi Kunci Otoritas (jika ada)
    let authority_validator_keys: Option<Arc<ValidatorKeys>> = if args.is_authority {
        let keystore_path = args.keystore_path.expect("Node authority harus dijalankan dengan --keystore-path");
        let vrf_priv_key_hex = args.vrf_priv_key.expect("Node authority harus dijalankan dengan --vrf-private-key");

        info!("Membuka keystore dari: {}", keystore_path);
        let keystore = Keystore::from_path(&keystore_path)?;

        let password = match args.password {
            Some(p) => {
                info!("Menggunakan kata sandi yang disediakan dari argumen CLI.");
                p
            }
            None => {
                println!("🔒 Masukkan kata sandi untuk keystore '{}':", keystore_path);
                read_password()?
            }
        };

        // println!("🔒 Masukkan kata sandi untuk keystore '{}':", keystore_path);
        // let password = read_password()?;

        let sk_bytes_vec = keystore.decrypt(&password)?;
        let pk_bytes = hex::decode(&keystore.public_key)?;

        let signing_keys = KeyPair::from_key_bytes(&pk_bytes, &sk_bytes_vec)?;
        let signing_address = public_key_to_address(&signing_keys.public_key_bytes());
        info!("Menjalankan sebagai NODE OTORITAS dengan alamat: 0x{}", hex::encode(signing_address.as_ref()));
        
        let vrf_secret_bytes = hex::decode(vrf_priv_key_hex)?;
        let vrf_secret = SchnorrkelSecretKey::from_bytes(&vrf_secret_bytes)
            .map_err(|_| "VRF private key tidak valid. Pastikan panjangnya 64-byte.")?;
        let vrf_keys = vrf_secret.to_keypair(); 
        
        Some(Arc::new(ValidatorKeys { signing_keys, vrf_keys }))
    } else {
        info!("Menjalankan sebagai NODE REGULER.");
        None
    };

    // Inisialisasi Blockchain & Mempool
    let blockchain = Arc::new(Mutex::new(Blockchain::new(&args.db_path, &args.vk_path)?));
    let mempool = Arc::new(Mempool::new());

    // Inisialisasi Kanal Komunikasi
    let (tx_gossip, rx_gossip) = mpsc::channel::<ChainMessage>(100);
    let (tx_sync_cmd, rx_sync_cmd) = mpsc::channel::<SyncRequest>(10);
    let (tx_sync_resp, _) = broadcast::channel::<SyncResponse>(100);
    let (p2p_to_consensus_tx, mut p2p_to_consensus_rx) = mpsc::channel::<ConsensusMessage>(100);
    
    let consensus_gossip_clone = tx_gossip.clone();
    let rpc_gossip_clone = tx_gossip.clone();
    let p2p_gossip_clone = tx_gossip.clone();
    let peer_counter = Arc::new(AtomicUsize::new(0));

    let consensus_sync_cmd_tx = tx_sync_cmd.clone();
    let sync_manager_cmd_tx = tx_sync_cmd.clone();
    let mempool_sync_cmd_tx = tx_sync_cmd.clone();
    let p2p_resp_tx = tx_sync_resp.clone();

    // =========================================================================
    // TASK KONSENSUS (REWORKED DENGAN BFT STATE MACHINE)
    // =========================================================================
    let consensus_blockchain_clone = Arc::clone(&blockchain);
    let consensus_mempool_clone = Arc::clone(&mempool);
    let authority_keys_clone = authority_validator_keys.clone();
    let consensus_is_syncing_clone = Arc::clone(&is_syncing);

    tokio::spawn(async move {
        if let Some(validator_keys) = authority_keys_clone {
            tokio::time::sleep(Duration::from_secs(10)).await;

            let my_address = public_key_to_address(&validator_keys.signing_keys.public_key_bytes());
            
            let (initial_height, initial_schedule) = {
                let chain_guard = consensus_blockchain_clone.lock().unwrap();
                let height = chain_guard.chain.last().map_or(1, |b| b.header.index + 1);
                let schedule = determine_proposer_schedule(
                    &chain_guard.state.validators, 
                    &chain_guard, 
                );
                (height, schedule)
            };
            let mut state = ConsensusState::new(initial_height, initial_schedule);
            
            let mut future_round_votes: HashMap<u64, HashMap<Address, Vote>> = HashMap::new();
            const BASE_CONSENSUS_TIMEOUT: Duration = Duration::from_secs(15);
            let mut last_progress_time = Instant::now();

            fn start_new_round(state: &mut ConsensusState, new_round_option: Option<u64>) {
                let new_round = new_round_option.unwrap_or(state.round + 1);

                warn!("[BFT h:{} r:{}] Memulai ronde baru: {}", state.height, state.round, new_round);
                state.round = new_round; // Langsung atur ke ronde baru
                state.step = ConsensusStep::Propose;
                state.current_proposal = None;
                state.prevotes.clear();
                state.precommits.clear();

                // Setelah memasuki ronde baru, periksa apakah kita sudah punya
                // proposal yang dibuffer untuk ronde ini. (Logika ini sudah ada dan bagus)
                if let Some(buffered_proposal) = state.buffered_proposals.remove(&state.round) {
                    info!("[BFT h:{} r:{}] Menemukan proposal yang dibuffer untuk ronde ini. Memproses sekarang...", state.height, state.round);
                    state.current_proposal = Some(buffered_proposal);
                    state.step = ConsensusStep::Prevote;
                }
            }

            async fn process_buffered_votes(
                state: &mut ConsensusState, 
                threshold: usize, 
                p2p_sender: &mpsc::Sender<ChainMessage>, 
                my_address: Address, 
                validator_keys: &Arc<ValidatorKeys>,
                mempool_hash: Vec<u8>,
            ) {
                // Jika kita memiliki suara yang disimpan untuk ronde yang baru saja kita masuki...
                if let Some(buffered) = state.buffered_prevotes.remove(&state.round) {
                    info!("[BFT h:{} r:{}] Memproses {} Prevote dari buffer untuk mengejar ketinggalan.", state.height, state.round, buffered.len());
                    for vote in buffered {
                        state.prevotes.insert(vote.voter_address, vote);
                    }
                    // Jika suara dari buffer sudah cukup untuk mencapai kuorum, langsung kirim Precommit
                    if state.step == ConsensusStep::Prevote && state.prevotes.len() > threshold {
                        info!("[BFT h:{} r:{}] Kuorum Prevote tercapai dari buffer! Mengirim Precommit.", state.height, state.round);
                        state.step = ConsensusStep::Precommit;
                        let precommit = Vote::new(
                            state.current_proposal.as_ref().unwrap().header.message_to_sign(), 
                            state.height, 
                            state.round, 
                            my_address,
                            mempool_hash,
                        ).sign(&validator_keys.signing_keys);
                        p2p_sender.send(ChainMessage::NewConsensusMessage(ConsensusMessage::Precommit(precommit))).await.ok();
                    }
                }
            }

            loop {
                let (current_chain_height, is_chain_empty) = {
                    let chain_guard = consensus_blockchain_clone.lock().unwrap();
                    let height = chain_guard.chain.last().map_or(0, |b| b.header.index);
                    (height, chain_guard.chain.is_empty())
                };
                
                if state.height <= current_chain_height || (is_chain_empty && state.height > 1) {
                    let new_height = current_chain_height + 1;
                    warn!("[BFT Self-Correction] State konsensus tertinggal (di h:{}) sementara chain sudah di h:{}. Mereset ke h:{}", state.height, current_chain_height, new_height);
                    
                    // Buat ulang state konsensus dari awal berdasarkan ketinggian blockchain yang benar.
                    let new_schedule = {
                        let chain_guard = consensus_blockchain_clone.lock().unwrap();
                        determine_proposer_schedule(&chain_guard.state.validators, &chain_guard)
                    };
                    state = ConsensusState::new(new_height, new_schedule);
                }

                // Jeda konsensus jika node sedang sinkronisasi
                if *consensus_is_syncing_clone.lock().unwrap() {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                // Hitung durasi timeout untuk ronde saat ini
                let my_mempool_hash = consensus_mempool_clone.calculate_mempool_hash();
                let current_timeout = BASE_CONSENSUS_TIMEOUT * 2u32.pow(state.round as u32);
                let check_interval = tokio::time::sleep(Duration::from_secs(1));

                select! {
                    // =========================================================================
                    // PENANGANAN PESAN MASUK DARI P2P (DENGAN LOGIKA SINKRONISASI)
                    // =========================================================================
                    Some(message) = p2p_to_consensus_rx.recv() => {
                        let (msg_height, msg_round) = match &message {
                            ConsensusMessage::Propose(b) => (b.header.index, b.round),
                            ConsensusMessage::Prevote(v) | ConsensusMessage::Precommit(v) => (v.height, v.round),
                            ConsensusMessage::ProposeHash(_) | ConsensusMessage::GetProposal(_) => {
                                continue;
                            }
                        };

                        // Validasi awal
                        let (is_synced, is_valid_vote, threshold) = {
                            let chain = consensus_blockchain_clone.lock().unwrap();
                            let local_height = chain.chain.last().map_or(0, |b| b.header.index);
                            let synced = msg_height == local_height + 1;
                            if !synced {
                                warn!("[BFT] Mengabaikan pesan untuk height {}, karena state lokal berada di height {}.", msg_height, local_height);
                            }
                            // Verifikasi tanda tangan vote (jika relevan)
                            let valid_vote = match &message {
                                ConsensusMessage::Prevote(v) | ConsensusMessage::Precommit(v) => chain.verify_vote(v).is_ok(),
                                _ => true, // Bukan vote, anggap valid untuk langkah ini
                            };
                            // Dapatkan threshold
                            let num_validators = chain.state.validators.len();
                            let calculated_threshold = (num_validators * 2) / 3;
                            // `chain` (MutexGuard) akan dilepaskan secara otomatis di akhir blok ini
                            (synced, valid_vote, calculated_threshold)
                        };

                        // Sekarang berada di luar 'lock' dan aman untuk menggunakan '.await'
                        if !is_synced || !is_valid_vote {
                            continue;
                        }
                        // Abaikan pesan dari ronde yang sudah lewat
                        if msg_round < state.round {
                            continue;
                        }
                        last_progress_time = Instant::now();

                        // Pesan untuk ronde di masa depan. Simpan di buffer, jangan proses sekarang.
                        if msg_round > state.round {
                            match message {
                                ConsensusMessage::Propose(block) => {
                                    let is_valid_proposal = {
                                        let mut chain = consensus_blockchain_clone.lock().unwrap();
                                        chain.process_block_proposal(&block).is_ok()
                                    };
                                    if is_valid_proposal {
                                        warn!("[BFT h:{} r:{}] Menerima proposal valid untuk ronde masa depan (r:{}). Menyimpan ke buffer.", state.height, state.round, block.round);
                                        state.buffered_proposals.insert(block.round, block);
                                    }
                                }
                                ConsensusMessage::Prevote(vote) => {
                                    let round_voters = future_round_votes.entry(msg_round).or_default();
                                    round_voters.insert(vote.voter_address, vote);

                                    if round_voters.len() >= threshold {
                                        warn!("[BFT h:{} r:{}] Mayoritas suara terdeteksi untuk ronde masa depan (r:{}). Melompat ke ronde baru!", state.height, state.round, msg_round);
                                        
                                        start_new_round(&mut state, Some(msg_round));
                                        last_progress_time = Instant::now(); 
                                        
                                        process_buffered_votes(&mut state, threshold, &consensus_gossip_clone, my_address, &validator_keys, my_mempool_hash.clone()).await;
                                    }
                                }
                                _ => {}
                            }
                            continue; // Penting: hentikan pemrosesan setelah menyimpan ke buffer
                        }

                        // Jika kita menerima pesan yang valid untuk ronde saat ini,
                        // itu adalah tanda kemajuan. Reset timer!
                        last_progress_time = Instant::now();

                        match message {
                            ConsensusMessage::Propose(block) => {
                                if block.round == state.round && state.step == ConsensusStep::Propose {
                                    let is_valid_proposal = {
                                        let mut chain = consensus_blockchain_clone.lock().unwrap();
                                        chain.process_block_proposal(&block).is_ok()
                                    };
                                    if is_valid_proposal {
                                        info!("[BFT h:{} r:{}] Menerima proposal valid. Mengirim Prevote.", state.height, state.round);
                                        state.current_proposal = Some(block.clone());
                                        state.step = ConsensusStep::Prevote;

                                        let vote = Vote::new(block.header.message_to_sign(), state.height, state.round, my_address, my_mempool_hash.clone())
                                            .sign(&validator_keys.signing_keys);
                                        consensus_gossip_clone.send(ChainMessage::NewConsensusMessage(ConsensusMessage::Prevote(vote))).await.ok();

                                        process_buffered_votes(&mut state, threshold, &consensus_gossip_clone, my_address, &validator_keys, my_mempool_hash.clone()).await;
                                    } else {
                                        warn!("[BFT h:{} r:{}] Menerima proposal TIDAK VALID. Proposal diabaikan.", state.height, state.round);
                                    }
                                }
                                else if block.round > state.round {
                                    let is_valid_proposal = {
                                        let mut chain = consensus_blockchain_clone.lock().unwrap();
                                        chain.process_block_proposal(&block).is_ok()
                                    };
                                    if is_valid_proposal {
                                        warn!("[BFT h:{} r:{}] Menerima proposal valid untuk ronde masa depan (r:{}). Menyimpan ke buffer.", state.height, state.round, block.round);
                                        state.buffered_proposals.insert(block.round, block);
                                    }
                                }
                            }
                            ConsensusMessage::Prevote(vote) => {
                                // Jika kita menerima vote untuk ronde di masa depan, simpan di buffer.
                                if vote.round > state.round && consensus_blockchain_clone.lock().unwrap().verify_vote(&vote).is_ok() {
                                    warn!("[BFT] Menerima Prevote untuk ronde masa depan (r:{}). Menyimpan ke buffer.", vote.round);
                                    state.buffered_prevotes.entry(vote.round).or_default().push(vote);
                                } 
                                // Jika vote untuk ronde saat ini, proses seperti biasa.
                                else if vote.round == state.round && state.step >= ConsensusStep::Prevote && consensus_blockchain_clone.lock().unwrap().verify_vote(&vote).is_ok() {
                                    // PERIKSA 1: Verifikasi tanda tangan vote.
                                    if consensus_blockchain_clone.lock().unwrap().verify_vote(&vote).is_err() {
                                        continue;
                                    }
                                    // Pastikan kita memiliki proposal dan hash-nya cocok dengan yang divoting.
                                    if let Some(proposal) = &state.current_proposal {
                                        if proposal.header.message_to_sign() != vote.block_hash {
                                            warn!("[BFT h:{} r:{}] Menerima Prevote untuk hash blok yang salah. Diabaikan.", state.height, state.round);
                                            continue;
                                        }
                                    } else {
                                        // Jika kita tidak punya proposal, kita tidak bisa memproses Prevote.
                                        warn!("[BFT h:{} r:{}] Menerima Prevote tapi tidak punya proposal. Diabaikan.", state.height, state.round);
                                        continue;
                                    }
                                             
                                    // Jika semua pemeriksaan lolos, baru kita hitung suaranya.
                                    if state.prevotes.insert(vote.voter_address, vote).is_none() {
                                    }
                                    if state.prevotes.len() >= threshold && state.step == ConsensusStep::Prevote {
                                        info!("[BFT h:{} r:{}] Kuorum Prevote! Mengirim Precommit.", state.height, state.round);
                                        state.step = ConsensusStep::Precommit;
                                        
                                        let precommit = Vote::new(state.current_proposal.as_ref().unwrap().header.message_to_sign(), state.height, state.round, my_address, my_mempool_hash.clone())
                                            .sign(&validator_keys.signing_keys);
                                        
                                        if state.precommits.insert(my_address, precommit.clone()).is_none() {}
                                        consensus_gossip_clone.send(ChainMessage::NewConsensusMessage(ConsensusMessage::Precommit(precommit))).await.ok();
                                    }
                                }
                            }
                            ConsensusMessage::Precommit(vote) => {
                                if vote.round == state.round && state.step >= ConsensusStep::Precommit {
                                    // PERIKSA 1: Verifikasi tanda tangan vote.
                                    if consensus_blockchain_clone.lock().unwrap().verify_vote(&vote).is_err() {
                                        continue; // Abaikan vote jika tanda tangan tidak valid.
                                    }
                                    // Pastikan memiliki proposal dan hash-nya cocok dengan yang divoting.
                                    // Ini mencegah memfinalisasi blok yang salah.
                                    if let Some(proposal) = &state.current_proposal {
                                        if proposal.header.message_to_sign() != vote.block_hash {
                                            warn!("[BFT h:{} r:{}] Menerima Precommit untuk hash blok yang salah. Diabaikan.", state.height, state.round);
                                            continue;
                                        }
                                    } else {
                                        // Jika tidak punya proposal sama sekali, kita tidak bisa memproses precommit.
                                        warn!("[BFT h:{} r:{}] Menerima Precommit tapi tidak punya proposal. Diabaikan.", state.height, state.round);
                                        continue;
                                    }
                                    // Jika semua pemeriksaan lolos, baru kita hitung suaranya.
                                    if state.precommits.insert(vote.voter_address, vote).is_none() {
                                    }
                                    if state.precommits.len() >= threshold {
                                        info!("[BFT h:{} r:{}] Kuorum Precommit! Blok FINAL.", state.height, state.round);
                                        let final_block = state.current_proposal.clone().unwrap();
                                            
                                        let final_block_for_commit = final_block.clone();

                                        let commit_result = {
                                            let mut chain = consensus_blockchain_clone.lock().unwrap();
                                            chain.finalize_and_commit_block(final_block_for_commit)
                                        }; // Kunci dilepaskan di sini

                                        match commit_result {
                                            Ok(confirmed_txs) => {
                                                info!("[BFT] Blok #{} berhasil di-commit.", state.height);
                                                
                                                {
                                                    let chain = consensus_blockchain_clone.lock().unwrap();
                                                    
                                                    // Hapus hanya transaksi yang sudah dikonfirmasi
                                                    consensus_mempool_clone.remove_transactions(&confirmed_txs);
                                                    
                                                    info!("[BFT] Memvalidasi ulang mempool terhadap state baru...");
                                                    consensus_mempool_clone.revalidate_against_new_state(&chain.state);

                                                    let new_schedule = determine_proposer_schedule(
                                                        &chain.state.validators, 
                                                        &chain, 
                                                    );
                                                    state = state.reset_for_next_height(new_schedule);
                                                } // <-- Kunci dilepaskan di sini setelah semua selesai
                                                
                                                last_progress_time = Instant::now();
                                            }, 

                                            Err(e) => {
                                                error!("[BFT] Gagal commit blok final karena divergensi state: {}. Memasuki mode pemulihan...", e);
                                                
                                                *consensus_is_syncing_clone.lock().unwrap() = true;
                                                consensus_mempool_clone.clear();

                                                // Gunakan Sender yang sudah di-clone dengan benar
                                                if let Err(e) = consensus_sync_cmd_tx.send(SyncRequest::GetMempoolTxHashes).await {
                                                    error!("[BFT Recovery] Gagal mengirim perintah sinkronisasi mempool: {}", e);
                                                }

                                                start_new_round(&mut state, None);
                                            }
                                        }
                                    }
                                }
                            }
                            ConsensusMessage::ProposeHash(_) | ConsensusMessage::GetProposal(_) => {}
                        }
                    }

                    // =========================================================================
                    // PENANGANAN TIMEOUT SECARA AKTIF (DENGAN LOGIKA BACKOFF)
                    // =========================================================================
                    _ = check_interval => {
                        // Setiap interval pendek (1 detik), periksa apakah sudah terlalu lama tidak ada kemajuan.
                        if last_progress_time.elapsed() >= current_timeout {
                            warn!("[BFT h:{} r:{}] Timeout karena tidak ada kemajuan selama {:?}. Memulai ronde baru!", state.height, state.round, current_timeout);
                            
                            start_new_round(&mut state, None);
                            last_progress_time = Instant::now(); // Reset timer untuk ronde baru

                            // Coba menjadi proposer segera setelah memulai ronde baru
                            let proposal_data = {
                                
                                let mut chain = consensus_blockchain_clone.lock().unwrap();
                                
                                if state.step == ConsensusStep::Propose {
                                    let proposer_index = state.round as usize % state.proposer_schedule.len();
                                    // Dapatkan proposer yang dijadwalkan untuk ronde saat ini
                                    if let Some(scheduled_proposer) = state.proposer_schedule.get(proposer_index) {
                                        // Periksa apakah SAYA adalah proposer yang dijadwalkan
                                        if *scheduled_proposer == my_address {
                                            info!("[BFT h:{} r:{}] Saya adalah proposer yang dijadwalkan. Menyiapkan proposal...", state.height, state.round);

                                            let candidate_txs = consensus_mempool_clone.get_transactions(MAX_TRANSACTIONS_PER_BLOCK);

                                            let mut transactions_for_block = Vec::new();
                                            let mut gas_used_in_block: u64 = 0;
                                            const BLOCK_GAS_LIMIT: u64 = 30_000_000; // Contoh batas gas per blok

                                            // 2. Validasi kandidat satu per satu untuk menyaring "racun"
                                            for tx in candidate_txs {
                                                if gas_used_in_block + tx.data.base_gas_cost() > BLOCK_GAS_LIMIT {
                                                    break; // Blok sudah penuh
                                                }

                                                let mut potential_next_txs = transactions_for_block.clone();
                                                potential_next_txs.push(tx.clone());

                                                // 3. Coba hitung state root dengan transaksi baru
                                                match chain.calculate_next_state_root(&potential_next_txs, my_address) {
                                                    Ok(_) => {
                                                        // Sukses! Transaksi ini valid dan bisa dimasukkan ke blok.
                                                        transactions_for_block.push(tx);
                                                        gas_used_in_block += transactions_for_block.last().unwrap().data.base_gas_cost();
                                                    }
                                                    Err(e) => {
                                                        // Gagal! Ini adalah transaksi beracun.
                                                        // Catat dan hapus secara permanen dari mempool lokal.
                                                        warn!("[BFT Proposer] Membuang transaksi tidak valid dari mempool (hash: {}). Penyebab: {}", hex::encode(tx.message_hash()), e);
                                                        consensus_mempool_clone.remove_single_transaction(&tx);
                                                    }
                                                }
                                            }

                                            let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
                
                                            // Hitung state root. `transactions_for_block` bisa saja kosong.
                                            if let Ok(final_state_root) = chain.calculate_next_state_root(&transactions_for_block, my_address) {
                                                let vrf_output = vec![0; 32];
                                                let vrf_proof = vec![0; 64];
                                                
                                                let new_block = chain.create_block(
                                                    &validator_keys.signing_keys, 
                                                    transactions_for_block, // Ini bisa jadi Vec kosong
                                                    final_state_root, 
                                                    vrf_output, 
                                                    vrf_proof, 
                                                    timestamp, 
                                                    state.round
                                                );

                                                if new_block.transactions.is_empty() {
                                                    info!("[BFT Proposer] Mempool kosong. Mengajukan proposal BLOK KOSONG untuk menjaga liveness.");
                                                }

                                                Some(new_block)
                                            } else {
                                                error!("[BFT Proposer] KRITIS: Gagal menghitung state root akhir bahkan setelah menyaring transaksi.");
                                                None
                                            }
                                        } else { None }
                                    } else {
                                        warn!("[BFT h:{} r:{}] Tidak ada proposer yang dijadwalkan untuk ronde ini. Mungkin semua validator gagal?", state.height, state.round);
                                        None
                                    }
                                } else { None }
                            };

                            // Sekarang kita berada di luar scope lock, kita aman untuk melakukan .await
                            if let Some(new_block) = proposal_data {
                                let proposal_msg = ConsensusMessage::Propose(new_block.clone());
                                consensus_gossip_clone.send(ChainMessage::NewConsensusMessage(proposal_msg)).await.ok();
                                
                                // Perbarui state internal setelah mengirim pesan
                                state.current_proposal = Some(new_block.clone());
                                state.step = ConsensusStep::Prevote;

                                let self_vote = Vote::new(new_block.header.message_to_sign(), state.height, state.round, my_address, my_mempool_hash.clone())
                                    .sign(&validator_keys.signing_keys);
                                consensus_gossip_clone.send(ChainMessage::NewConsensusMessage(ConsensusMessage::Prevote(self_vote))).await.ok();
                            }
                            // Setelah memulai ronde baru, langsung coba proses vote yang mungkin sudah menunggu di buffer
                            let threshold = (consensus_blockchain_clone.lock().unwrap().state.validators.len() * 2) / 3;
                            process_buffered_votes(&mut state, threshold, &consensus_gossip_clone, my_address, &validator_keys, my_mempool_hash).await;
                        }
                    }
                }
            }
        }
    });

    // =========================================================================
    // TASK SYNC MANAGER
    // =========================================================================
    let sync_blockchain_clone = Arc::clone(&blockchain);
    let sync_snapshot_dir = snapshot_dir.clone();
    let sync_is_syncing_clone = Arc::clone(&is_syncing);
    let mut sync_manager_rx_resp = tx_sync_resp.subscribe();

    tokio::spawn(async move {
        let mut sync_state = SyncState::Idle;
        let mut proactive_check_interval = interval(Duration::from_secs(15));

        loop {
            select! {
                _ = proactive_check_interval.tick(), if matches!(sync_state, SyncState::Idle) => {
                    info!("SYNC_MANAGER (Proaktif): Memeriksa status sinkronisasi...");
                    // Kirim permintaan metadata untuk mendapatkan gambaran state jaringan
                    if sync_manager_cmd_tx.send(SyncRequest::GetSnapshotMetadata).await.is_err() {
                        warn!("SYNC_MANAGER (Proaktif): Gagal mengirim permintaan metadata.");
                    }
                }

                Ok(response) = sync_manager_rx_resp.recv() => {
                    let mut next_state = None;

                    if let SyncResponse::TxsByHash(txs) = response {
                        let mut is_syncing = sync_is_syncing_clone.lock().unwrap();
                        if *is_syncing {
                             info!("SYNC_MANAGER (Recovery): Sinkronisasi mempool selesai setelah menerima {} transaksi. Melanjutkan konsensus.", txs.len());
                            *is_syncing = false;
                        }
                        continue;
                    }

                    match &mut sync_state {
                        SyncState::Idle => {
                            let mut had_error = false;
                            let mut last_received_index: Option<u64> = None;

                            match response {
                                // KASUS 1: Alur normal, memeriksa snapshot secara periodik
                                SyncResponse::SnapshotMetadata(Some(metadata)) => {
                                    let (local_height, local_block_exists) = {
                                        let chain = sync_blockchain_clone.lock().unwrap();
                                        let height = chain.chain.last().map_or(0, |b| b.header.index);
                                        let exists = !chain.chain.is_empty();
                                        (height, exists)
                                    };

                                    info!("SYNC_MANAGER: Menerima metadata snapshot (tinggi: {}). Tinggi lokal: {}.", metadata.height, local_height);

                                    if metadata.height > local_height + SNAPSHOT_SYNC_THRESHOLD {
                                        *sync_is_syncing_clone.lock().unwrap() = true;
                                        info!("SYNC_MANAGER: Memasuki mode sinkronisasi SNAPSHOT. Konsensus dijeda.");
                                        let temp_path = sync_snapshot_dir.join(format!("downloading_{}", metadata.file_name));
                                        match OpenOptions::new().write(true).create(true).truncate(true).open(&temp_path) {
                                            Ok(temp_file) => {
                                                let _ = sync_manager_cmd_tx.send(SyncRequest::GetSnapshotChunk { file_name: metadata.file_name.clone(), chunk_index: 0 }).await;
                                                next_state = Some(SyncState::DownloadingSnapshot { metadata, temp_file, next_chunk: 1 });
                                            },
                                            Err(e) => error!("SYNC_MANAGER: Gagal membuat file snapshot sementara: {}", e),
                                        }
                                    } else if metadata.height > local_height || (metadata.height == 0 && !local_block_exists) {
                                        info!("SYNC_MANAGER: Perlu sinkronisasi blok. Memasuki mode sinkronisasi BLOK.");
                                        *sync_is_syncing_clone.lock().unwrap() = true;
                                        let _ = sync_manager_cmd_tx.send(SyncRequest::GetBlocks { since_index: local_height }).await;
                                        next_state = Some(SyncState::SyncingBlocks);
                                    }
                                }

                                // KASUS 2: Menerima blok secara tak terduga (dipicu oleh p2p)
                                SyncResponse::Blocks { blocks } => {
                                    if !blocks.is_empty() {
                                        info!("SYNC_MANAGER (IDLE): Menerima blok dari pemicu reaktif. Memulai sinkronisasi...");
                                        *sync_is_syncing_clone.lock().unwrap() = true;
                                        
                                        // Simpan indeks blok terakhir yang diterima
                                        last_received_index = Some(blocks.last().unwrap().header.index);
                                        
                                        {
                                            let mut chain = sync_blockchain_clone.lock().unwrap();
                                            for block in blocks {
                                                if chain.chain.last().map_or(true, |b| block.header.index > b.header.index) {
                                                    if let Err(e) = chain.finalize_and_commit_block(block) {
                                                        error!("SYNC_MANAGER (IDLE): Gagal menerapkan blok awal: {}. Menghentikan sync.", e);
                                                        *sync_is_syncing_clone.lock().unwrap() = false;
                                                        had_error = true; // Set flag error
                                                        break; 
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }

                            if had_error {
                                next_state = Some(SyncState::Idle);
                            } else if let Some(last_idx) = last_received_index {
                                // Jika tidak ada error dan menerima blok, lanjutkan sinkronisasi
                                let next_index_to_request = last_idx + 1;
                                let _ = sync_manager_cmd_tx.send(SyncRequest::GetBlocks { since_index: next_index_to_request }).await;
                                next_state = Some(SyncState::SyncingBlocks);
                            }
                        }

                        SyncState::DownloadingSnapshot { metadata, temp_file, next_chunk } => {
                            if let SyncResponse::SnapshotChunk { data } = response {
                                if data.is_empty() {
                                    info!("SYNC_MANAGER: Semua chunk snapshot telah diunduh. Menerapkan snapshot...");
                                    
                                    let temp_path = sync_snapshot_dir.join(format!("downloading_{}", metadata.file_name));
                                    let final_path = sync_snapshot_dir.join(&metadata.file_name);
                                    if let Err(e) = std::fs::rename(&temp_path, &final_path) {
                                        error!("SYNC_MANAGER: Gagal mengganti nama file snapshot: {}", e);
                                        *sync_is_syncing_clone.lock().unwrap() = false;
                                    } else {
                                        {
                                            let mut chain = sync_blockchain_clone.lock().unwrap();
                                            match snapshot::load_snapshot(Arc::clone(&chain.state.db), &sync_snapshot_dir, &metadata) {
                                                Ok(_) => {
                                                    info!("SYNC_MANAGER: Snapshot berhasil diterapkan. Mengatur ulang chain lokal ke tinggi #{}.", metadata.height);
                                                    chain.chain.clear();
                                                    chain.state.state_root = metadata.state_root;
                                                },
                                                Err(e) => error!("SYNC_MANAGER: KRITIS - Gagal menerapkan snapshot: {}", e),
                                            }
                                        }
                                        *sync_is_syncing_clone.lock().unwrap() = false;
                                        info!("SYNC_MANAGER: Sinkronisasi snapshot selesai. Kembali ke mode Idle.");
                                    }
                                    next_state = Some(SyncState::Idle);
                                } else {
                                    if let Err(e) = temp_file.write_all(&data) {
                                        error!("SYNC_MANAGER: Gagal menulis chunk ke file sementara: {}", e);
                                        *sync_is_syncing_clone.lock().unwrap() = false;
                                        next_state = Some(SyncState::Idle);
                                    } else {
                                        info!("SYNC_MANAGER: Mengunduh chunk {}/{}", *next_chunk, metadata.total_chunks);
                                        let _ = sync_manager_cmd_tx.send(SyncRequest::GetSnapshotChunk { file_name: metadata.file_name.clone(), chunk_index: *next_chunk }).await;
                                        *next_chunk += 1;
                                    }
                                }
                            }
                        }

                        SyncState::SyncingBlocks => {
                            if let SyncResponse::Blocks { blocks } = response {
                                if blocks.is_empty() {
                                    info!("SYNC_MANAGER: Sinkronisasi blok selesai. Melanjutkan konsensus.");
                                    *sync_is_syncing_clone.lock().unwrap() = false;
                                    next_state = Some(SyncState::Idle);
                                } else {
                                    let last_received_index = blocks.last().unwrap().header.index;
                                    info!("SYNC_MANAGER: Menerima {} blok untuk sinkronisasi, hingga blok #{}.", blocks.len(), last_received_index);

                                    let mut had_error = false;
                                    { // <-- Mulai scope baru untuk mengunci
                                        let mut chain = sync_blockchain_clone.lock().unwrap();
                                        for block in blocks {
                                            if chain.chain.last().map_or(true, |b| block.header.index > b.header.index) {
                                                if let Err(e) = chain.finalize_and_commit_block(block) {
                                                    error!("SYNC_MANAGER: Gagal menambahkan blok saat sinkronisasi: {}. Menghentikan sync.", e);
                                                    had_error = true;
                                                    break;
                                                }
                                            }
                                        }
                                    } // <-- Kunci (`chain`) secara otomatis dilepaskan di sini
                                    
                                    // Sekarang kita aman untuk melakukan .await
                                    if had_error {
                                        next_state = Some(SyncState::Idle);
                                    } else {
                                        // Minta blok BERIKUTNYA, bukan blok yang sama lagi.
                                        let next_index_to_request = last_received_index + 1;
                                        info!("SYNC_MANAGER: Melanjutkan sinkronisasi dari blok #{}.", next_index_to_request);
                                        let _ = sync_manager_cmd_tx.send(SyncRequest::GetBlocks { since_index: next_index_to_request }).await;
                                    }
                                }
                            }
                        }
                    }

                    if let Some(state) = next_state {
                        sync_state = state;
                    }
                }
            }
        }
    });

    // =========================================================================
    // TASK MEMPOOL SYNC 
    // =========================================================================
    let mempool_sync_mempool_clone = Arc::clone(&mempool);
    let mut mempool_sync_rx_resp = tx_sync_resp.subscribe();
    
    tokio::spawn(async move {
        let mut sync_interval = interval(Duration::from_secs(5));
        
        loop {
            sync_interval.tick().await;
            if let Err(e) = mempool_sync_cmd_tx.send(SyncRequest::GetMempoolTxHashes).await {
                warn!("MEMPOOL_SYNC: Gagal mengirim permintaan hash ke P2P: {}", e);
            }

            if let Ok(Ok(response)) = tokio::time::timeout(Duration::from_secs(2), mempool_sync_rx_resp.recv()).await {
                if let SyncResponse::MempoolTxHashes(peer_hashes) = response {
                    let local_hashes = mempool_sync_mempool_clone.get_all_hashes();
                    let local_set: HashSet<_> = local_hashes.into_iter().collect();
                    let missing_hashes: Vec<_> = peer_hashes.into_iter().filter(|h| !local_set.contains(h)).collect();
                    
                    if !missing_hashes.is_empty() {
                        info!("MEMPOOL_SYNC: Menemukan {} transaksi yang hilang, meminta dari peer...", missing_hashes.len());
                        let _ = mempool_sync_cmd_tx.send(SyncRequest::GetTxsByHash(missing_hashes)).await;
                    }
                }
            }
        }
    });

    // =========================================================================
    // TASK P2P & RPC
    // =========================================================================
    let p2p_blockchain_clone = Arc::clone(&blockchain);
    let p2p_mempool_clone = Arc::clone(&mempool);
    let p2p_snapshot_dir = snapshot_dir.to_str().unwrap().to_string(); 
    let p2p_peer_counter_clone = Arc::clone(&peer_counter);

    let p2p_future = p2p::run(
        p2p_blockchain_clone, 
        p2p_mempool_clone, 
        p2p_gossip_clone,
        rx_gossip, 
        rx_sync_cmd, 
        p2p_resp_tx,    
        tx_sync_cmd,        
        args.bootstrap_node, 
        args.p2p_port,
        p2p_to_consensus_tx,
        p2p_peer_counter_clone,
        p2p_snapshot_dir
    );

    let rpc_blockchain_clone = Arc::clone(&blockchain);
    let rpc_mempool_clone = Arc::clone(&mempool);
    let rpc_snapshot_dir = snapshot_dir.clone();
    let rpc_future = rpc::run(
        rpc_blockchain_clone, 
        rpc_mempool_clone, 
        rpc_gossip_clone, 
        args.rpc_port, 
        rpc_snapshot_dir,
    );

    // =========================================================================
    // TASK STATE PRUNING (PERIODIK)
    // =========================================================================
    let pruning_blockchain_clone = Arc::clone(&blockchain);
    tokio::spawn(async move {
        // Jalankan setiap 100 blok (sesuaikan interval sesuai kebutuhan)
        let mut pruning_interval = interval(Duration::from_secs(100 * 10)); // Asumsi 10 detik per blok
        const PRUNING_HORIZON: u64 = 100_000; // Simpan 100,000 state terakhir

        loop {
            pruning_interval.tick().await;
            info!("PRUNING_TASK: Memulai tugas pemangkasan state periodik.");
            let chain = pruning_blockchain_clone.lock().unwrap();
            if let Err(e) = chain.state.prune(PRUNING_HORIZON) {
                error!("PRUNING_TASK: Gagal melakukan pemangkasan state: {}", e);
            }
        }
    });

    tokio::try_join!(
        async { p2p_future.await.map_err(|e| e.into()) },
        async { rpc_future.await } 
    )?;

    Ok(())
}
