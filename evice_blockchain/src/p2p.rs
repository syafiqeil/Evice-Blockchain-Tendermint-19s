// src/p2p.rs

use libp2p::{
    futures::StreamExt,
    gossipsub::MessageAcceptance,
    swarm::{NetworkBehaviour, SwarmEvent},
    request_response::{self, ProtocolSupport},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol,
    gossipsub, identity, kad, noise,
};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{Ordering, AtomicUsize};
use std::time::{Duration, Instant};
use tokio::{select, sync::{mpsc, broadcast}};
use zstd::stream::{encode_all, decode_all};
use borsh::{BorshSerialize, BorshDeserialize};

use crate::blockchain::{Block, Blockchain, BlockchainError, ChainMessage};
use crate::mempool::Mempool;
use crate::Transaction;
use crate::consensus::ConsensusMessage;
use crate::snapshot::{SnapshotMetadata, read_snapshot_chunk};

// Tambahkan konstanta untuk manajemen skor
const INITIAL_PEER_SCORE: i32 = 0;
const MAX_PEER_SCORE: i32 = 100;
const BAN_THRESHOLD: i32 = -50;

// Penalti yang lebih signifikan
const PENALTY_INVALID_SIGNATURE: i32 = -50; // Kesalahan fatal, langsung mendekati ban
const PENALTY_BAD_BLOCK: i32 = -25;
const PENALTY_BAD_TRANSACTION: i32 = -10;
const PENALTY_DESERIALIZATION_ERROR: i32 = -5;

// Imbalan
const REWARD_VALID_MESSAGE: i32 = 2;

#[derive(Debug)]
#[allow(dead_code)]
struct PeerInfo {
    score: i32,
    last_seen: Instant,
    is_banned: bool,
    ban_until: Option<Instant>, 
}

impl PeerInfo {
    fn new() -> Self {
        Self {
            score: INITIAL_PEER_SCORE,
            last_seen: Instant::now(),
            is_banned: false,
            ban_until: None,
        }
    }

    // Fungsi untuk memberikan penalti dan mengecek apakah peer harus di-ban
    fn apply_penalty(&mut self, penalty: i32) {
        self.score = (self.score + penalty).max(BAN_THRESHOLD - 1); // Pastikan skor tidak jauh di bawah threshold
        if self.score <= BAN_THRESHOLD {
            self.is_banned = true;
            // Ban selama 30 menit
            self.ban_until = Some(Instant::now() + Duration::from_secs(1800)); 
            warn!("Peer di-ban karena skor mencapai {}", self.score);
        }
    }

    fn apply_reward(&mut self, reward: i32) {
        self.score = (self.score + reward).min(MAX_PEER_SCORE);
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    GetBlocks { since_index: u64 },
    GetSnapshotMetadata,
    GetSnapshotChunk { file_name: String, chunk_index: u32 },
    GetMempoolTxHashes,
    GetTxsByHash(Vec<Vec<u8>>),
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    Blocks { blocks: Vec<Block> },
    SnapshotMetadata(Option<SnapshotMetadata>),
    SnapshotChunk { data: Vec<u8> },
    MempoolTxHashes(Vec<Vec<u8>>),
    TxsByHash(Vec<Transaction>),
}

const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/evice-blockchain/sync/1.0");

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub req_resp: request_response::Behaviour<request_response::cbor::codec::Codec<SyncRequest, SyncResponse>>,
}

pub async fn run(
    blockchain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mempool>,
    tx_gossip: mpsc::Sender<ChainMessage>,
    mut rx_gossip: mpsc::Receiver<ChainMessage>,
    mut rx_sync_cmd: mpsc::Receiver<SyncRequest>,
    tx_sync_resp: broadcast::Sender<SyncResponse>,
    tx_sync_cmd: mpsc::Sender<SyncRequest>,
    bootstrap_node: Option<String>,
    p2p_port: u16,
    p2p_to_consensus_tx: mpsc::Sender<ConsensusMessage>,
    peer_counter: Arc<AtomicUsize>,
    snapshot_dir: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    info!("Peer ID lokal: {}", local_peer_id);

    // --- Konfigurasi Gossipsub untuk validasi pesan ---
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict) // Aktifkan validasi kustom
        .build()?;

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;
            let store = kad::store::MemoryStore::new(local_peer_id);
            let kademlia = kad::Behaviour::new(local_peer_id, store);

            let req_resp = request_response::Behaviour::new( 
                [(
                    SYNC_PROTOCOL,
                    ProtocolSupport::Full 
                )],

                request_response::Config::default(),
            );

            Ok(AppBehaviour {
                gossipsub,
                kademlia,
                req_resp,
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let topic = gossipsub::IdentTopic::new("evice-blockchain-topic");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    // Struktur data untuk peer scoring
    let peer_scores = Arc::new(Mutex::new(HashMap::<PeerId, PeerInfo>::new()));

    // Cache untuk melacak hash yang sudah kita lihat
    let seen_hashes = Arc::new(Mutex::new(lru::LruCache::<Vec<u8>, ()>::new(std::num::NonZeroUsize::new(10000).unwrap())));

    if let Some(addr_str) = bootstrap_node {
        let remote_addr = Multiaddr::from_str(&addr_str)?;
        if let Some(remote_peer_id) = remote_addr.iter().last().and_then(|proto| {
            if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
                Some(peer_id)
            } else {
                None
            }
        }) {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&remote_peer_id, remote_addr.clone());
            info!("Menambahkan bootstrap node: {}", remote_addr);
        } else {
            return Err("Alamat bootstrap node tidak mengandung PeerId yang valid.".into());
        }
    }

    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
        warn!("P2P: Gagal memulai Kademlia bootstrap: {:?}", e);
    }      
    
    // --- PERBAIKAN UNTUK LINUX: Gunakan 0.0.0.0 ---
    // Ini memungkinkan node untuk menerima koneksi dari mesin lain.
    let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse()?;
    swarm.listen_on(listen_addr)?;

    loop {
        select! {
            // Menangani pesan gossip yang harus disiarkan (dari konsensus/rpc)
            Some(message_to_broadcast) = rx_gossip.recv() => {
                let serialized_data = match borsh::to_vec(&message_to_broadcast) {
                    Ok(data) => data,
                    Err(e) => {
                        error!("P2P: Gagal serialize pesan gossip dengan Borsh: {:?}", e);
                        continue; // Lewati pesan yang tidak bisa di-serialize
                    }
                };

                let compressed_data = encode_all(&serialized_data[..], 3)?; // Level kompresi 3

                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), compressed_data) {
                    warn!("P2P: Gagal menyiarkan pesan gossip: {:?}", e);
                }
            }
            // --- Menangani perintah dari Sync Manager ---
            Some(request) = rx_sync_cmd.recv() => {
                // Cari peer acak yang terhubung untuk dikirimi permintaan
                let peer_to_send = swarm.connected_peers().next().cloned();
                if let Some(peer_id) = peer_to_send {
                     info!("P2P: Mengirim permintaan sinkronisasi {:?} ke peer {}", request, peer_id);
                     swarm.behaviour_mut().req_resp.send_request(&peer_id, request);
                } else {
                    warn!("P2P: Tidak ada peer terhubung untuk mengirim permintaan sinkronisasi.");
                }
            }

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Node mendengarkan di: {}/p2p/{}", address, local_peer_id);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        info!("Koneksi berhasil dibuat dengan peer: {}", peer_id);
                        peer_scores.lock().unwrap().entry(peer_id).or_insert_with(PeerInfo::new);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        peer_counter.fetch_add(1, Ordering::SeqCst);
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. })) => {
                        if let kad::QueryResult::GetClosestPeers(Ok(ok)) = result {
                            for peer_info in ok.peers {
                                if !swarm.is_connected(&peer_info.peer_id) {
                                    info!("KAD: Menemukan peer baru {:?}, mencoba terhubung...", peer_info.peer_id);
        
                                    swarm.dial(peer_info.peer_id).unwrap_or_else(|e| { 
                                        warn!("Gagal melakukan dial ke peer baru: {:?}", e);
                                    });
                                }
                            }
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        info!("Koneksi dengan peer {} ditutup.", peer_id);
                        peer_scores.lock().unwrap().remove(&peer_id);
                        peer_counter.fetch_add(1, Ordering::SeqCst);
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message_id,
                        message,
                    })) => {
                        let decompressed_data = match decode_all(&message.data[..]) {
                            Ok(data) => data,
                            Err(e) => {
                                warn!("P2P: Gagal dekompresi pesan dari {}: {}", propagation_source, e);
                                // Beri penalti dan tolak pesan
                                let mut scores = peer_scores.lock().unwrap();
                                let info = scores.entry(propagation_source).or_insert_with(PeerInfo::new);
                                info.apply_penalty(PENALTY_DESERIALIZATION_ERROR);
                                swarm.behaviour_mut().gossipsub.report_message_validation_result(&message_id, &propagation_source, MessageAcceptance::Reject);
                                continue;
                            }
                        };

                        let result = match ChainMessage::try_from_slice(&decompressed_data) {
                            Ok(chain_message) => {
                                let mut scores = peer_scores.lock().unwrap();
                                let info = scores.entry(propagation_source).or_insert_with(PeerInfo::new);

                                let gossip_clone = tx_gossip.clone();
                                let seen_hashes_clone = seen_hashes.clone();

                                let is_valid = match chain_message {
                                    ChainMessage::NewTransactionHash(hash) => {
                                        let mut seen = seen_hashes_clone.lock().unwrap();
                                        if seen.put(hash.clone(), ()).is_none() {
                                            // Jika hash ini baru, minta transaksi lengkapnya
                                            tokio::spawn(async move {
                                                gossip_clone.send(ChainMessage::GetTransaction(hash)).await.ok();
                                            });
                                        }
                                        true // Selalu terima hash
                                    },
                                    ChainMessage::GetTransaction(hash) => {
                                        if let Some(tx) = mempool.get_transaction_by_hash(&hash) {
                                             tokio::spawn(async move {
                                                gossip_clone.send(ChainMessage::NewTransaction(tx)).await.ok();
                                            });
                                        }
                                        true // Tidak perlu validasi lebih lanjut
                                    }
                                    ChainMessage::NewConsensusMessage(ConsensusMessage::ProposeHash(hash)) => {
                                        let mut seen = seen_hashes_clone.lock().unwrap();
                                        if seen.put(hash.clone(), ()).is_none() {
                                            // Minta proposal lengkap
                                            let get_proposal_msg = ConsensusMessage::GetProposal(hash);
                                            tokio::spawn(async move {
                                                gossip_clone.send(ChainMessage::NewConsensusMessage(get_proposal_msg)).await.ok();
                                            });
                                        }
                                        true
                                    },
                                    ChainMessage::NewConsensusMessage(ConsensusMessage::GetProposal(hash)) => {
                                        if let Some(block) = blockchain.lock().unwrap().get_block_by_hash(&hash) {
                                            let proposal_msg = ConsensusMessage::Propose(block.clone());
                                             tokio::spawn(async move {
                                                gossip_clone.send(ChainMessage::NewConsensusMessage(proposal_msg)).await.ok();
                                            });
                                        }
                                        true
                                    },
                                    ChainMessage::NewTransaction(tx) => {
                                        let chain = blockchain.lock().unwrap();
                                        let peer_id_str = propagation_source.to_string();

                                        match mempool.add_transaction(tx.clone(), &peer_id_str, &chain.state, &chain) {
                                            Ok(_) => {
                                                // Jika berhasil, beri imbalan pada peer.
                                                info.apply_reward(REWARD_VALID_MESSAGE);
                                                true // Tandai pesan sebagai valid
                                            },
                                            Err(e) => {
                                                // Jika gagal, beri penalti pada peer.
                                                warn!("P2P: Transaksi dari {} ditolak oleh mempool: {}", peer_id_str, e);
                                                // Tentukan penalti berdasarkan jenis error
                                                let penalty = if e == "Tanda tangan tidak valid" {
                                                    PENALTY_INVALID_SIGNATURE
                                                } else {
                                                    PENALTY_BAD_TRANSACTION
                                                };
                                                info.apply_penalty(penalty);
                                                false // Tandai pesan sebagai tidak valid
                                            }
                                        }
                                    }
                                    ChainMessage::NewConsensusMessage(consensus_msg) => {
                                        // Dapatkan state sinkronisasi sebelum melakukan validasi apa pun
                                        let (local_block_exists, msg_height) = {
                                            let chain = blockchain.lock().unwrap();
                                            let exists = !chain.chain.is_empty();
                                            let height = match &consensus_msg {
                                                ConsensusMessage::Propose(b) => b.header.index,
                                                ConsensusMessage::Prevote(v) | ConsensusMessage::Precommit(v) => v.height,
                                                 ConsensusMessage::ProposeHash(_) | ConsensusMessage::GetProposal(_) => {
                                                    // Ambil tinggi blok terakhir sebagai referensi
                                                    chain.chain.last().map_or(0, |b| b.header.index)
                                                }
                                            };
                                            (exists, height)
                                        };

                                        // Jika kita belum punya genesis dan pesan ini untuk blok setelahnya,
                                        // jangan beri penalti. Anggap valid untuk sementara di lapisan P2P.
                                        // Biarkan logika BFT yang menanganinya.
                                        if !local_block_exists && msg_height > 0 {
                                            // Kirim pesan ke BFT untuk diabaikan, tapi jangan hukum peer.
                                            if p2p_to_consensus_tx.send(consensus_msg.clone()).await.is_err() {
                                                error!("P2P: Gagal mengirim pesan konsensus ke logika BFT.");
                                            }
                                            // Jangan beri penalti, cukup terima pesan untuk diproses lebih lanjut
                                            true 
                                        } else {
                                            // Jika kita sudah sinkron, jalankan validasi seperti biasa
                                            let is_msg_statically_valid = match &consensus_msg {
                                                ConsensusMessage::Propose(block) => {
                                                    let mut chain = blockchain.lock().unwrap();
                                                    match chain.process_block_proposal(&block) {
                                                        Ok(_) => {
                                                            if p2p_to_consensus_tx.send(consensus_msg.clone()).await.is_err() {
                                                                error!("P2P: Gagal mengirim proposal valid ke logika BFT.");
                                                            }
                                                            info.apply_reward(REWARD_VALID_MESSAGE);
                                                            true
                                                        },
                                                        Err(e) => {
                                                            // Gunakan `match` untuk menangani jenis error secara spesifik
                                                            match e {
                                                                // Jika errornya adalah karena kita tertinggal...
                                                                BlockchainError::InvalidIndex { .. } | BlockchainError::PreviousHashMismatch => {
                                                                    warn!("P2P: Menerima proposal usang ({}). Mengabaikan tanpa penalti.", e);
                                                                    
                                                                    // TRIGER SINKRONISASI:
                                                                    let local_height = chain.chain.last().map_or(0, |b| b.header.index);
                                                                    info!("SYNC TRIGGER: Terdeteksi tertinggal! Memulai sinkronisasi blok dari #{}", local_height);
                                                                    
                                                                    // Kloning sender channel agar bisa dipindahkan ke thread baru
                                                                    let sync_cmd_sender = tx_sync_cmd.clone();
                                                                    tokio::spawn(async move {
                                                                        if let Err(e) = sync_cmd_sender.send(SyncRequest::GetBlocks { since_index: local_height }).await {
                                                                            error!("P2P (async task): Gagal mengirim perintah sinkronisasi reaktif: {}", e);
                                                                        }
                                                                    });
                                                                    
                                                                    // Terima pesan ini agar tidak menghukum peer yang sebenarnya berada di depan kita.
                                                                    true 
                                                                },

                                                                // Untuk error fatal lainnya, tetap berikan penalti.
                                                                BlockchainError::InvalidSignature | BlockchainError::NotAValidator | BlockchainError::VrfVerificationFailed => {
                                                                    warn!("P2P: Menerima proposal SANGAT TIDAK VALID ({}). Menghukum peer {}...", e, propagation_source);
                                                                    info.apply_penalty(PENALTY_BAD_BLOCK);
                                                                    false
                                                                },
                                                                // Tangani semua kasus error lainnya
                                                                _ => {
                                                                    warn!("P2P: Proposal ditolak karena alasan lain: {}. Menghukum peer {}...", e, propagation_source);
                                                                    info.apply_penalty(PENALTY_BAD_BLOCK);
                                                                    false
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                ConsensusMessage::Prevote(vote) | ConsensusMessage::Precommit(vote) => {
                                                    let chain = blockchain.lock().unwrap();
                                                    if chain.verify_vote(vote).is_ok() {
                                                        true
                                                    } else {
                                                        info.apply_penalty(PENALTY_INVALID_SIGNATURE);
                                                        false
                                                    }
                                                }
                                                ConsensusMessage::ProposeHash(_) | ConsensusMessage::GetProposal(_) => {
                                                    true
                                                }
                                            };

                                            if is_msg_statically_valid {
                                                if p2p_to_consensus_tx.send(consensus_msg.clone()).await.is_err() {
                                                    error!("P2P: Gagal mengirim pesan konsensus ke logika BFT.");
                                                }
                                                info.apply_reward(REWARD_VALID_MESSAGE);
                                                true
                                            } else {
                                                false
                                            }
                                        }
                                    }
                                };
                                if is_valid { gossipsub::MessageAcceptance::Accept } else { gossipsub::MessageAcceptance::Reject }
                            }
                            Err(_) => {
                                let mut scores = peer_scores.lock().unwrap();
                                let info = scores.entry(propagation_source).or_insert_with(PeerInfo::new);
                                warn!("P2P: Menerima pesan gossipsub yang tidak dapat di-deserialisasi dari {}.", propagation_source);
                                info.apply_penalty(PENALTY_DESERIALIZATION_ERROR);
                                gossipsub::MessageAcceptance::Reject
                            }
                        };
                        if !swarm.behaviour_mut().gossipsub.report_message_validation_result(&message_id, &propagation_source, result) {
                            warn!("P2P: Gagal melaporkan hasil validasi pesan (fungsi mengembalikan false).");
                        }
                    }

                    SwarmEvent::Behaviour(AppBehaviourEvent::ReqResp(event)) => {
                        match event {
                            request_response::Event::Message { message, peer, .. } => {
                                match message {
                                    request_response::Message::Request { request, channel, .. } => {
                                        match request {
                                            SyncRequest::GetBlocks { since_index } => {
                                                let chain = blockchain.lock().unwrap();
                                                let blocks_to_send: Vec<Block> = chain.chain
                                                    .iter()
                                                    .filter(|block| {block.header.index >= since_index})
                                                    .cloned()
                                                    .take(100) // Batasi jumlah blok per respons
                                                    .collect();
                                                
                                                if !blocks_to_send.is_empty() {
                                                    info!("SYNC: Mengirim {} blok mulai dari #{} ke peer.", blocks_to_send.len(), blocks_to_send[0].header.index);
                                                }

                                                let response = SyncResponse::Blocks { blocks: blocks_to_send };
                                                let _ = swarm.behaviour_mut().req_resp.send_response(channel, response);
                                            }
                                            SyncRequest::GetSnapshotMetadata => {
                                                let mut metadata = crate::snapshot::find_latest_snapshot(&snapshot_dir).unwrap_or(None);
                                                // Jika tidak ada snapshot yang ditemukan, TAPI kita punya Blok Genesis,
                                                // buat metadata "virtual" untuk Blok #0.
                                                if metadata.is_none() {
                                                    let chain = blockchain.lock().unwrap();
                                                    if let Some(genesis_block) = chain.chain.get(0) {
                                                        info!("SYNC: Tidak ada snapshot, tapi memiliki genesis. Memberikan metadata untuk Blok #0.");
                                                        metadata = Some(crate::snapshot::SnapshotMetadata {
                                                            height: 0,
                                                            state_root: genesis_block.header.state_root.clone().try_into().unwrap(),
                                                            total_chunks: 1, // Tidak relevan, tapi harus diisi
                                                            file_name: "genesis".to_string(), // Placeholder
                                                        });
                                                    }
                                                }
                                                let response = SyncResponse::SnapshotMetadata(metadata);
                                                let _ = swarm.behaviour_mut().req_resp.send_response(channel, response);
                                            }
                                            SyncRequest::GetSnapshotChunk { file_name, chunk_index } => {
                                                let chunk_data = read_snapshot_chunk(&snapshot_dir, &file_name, chunk_index)
                                                    .unwrap_or_default()
                                                    .unwrap_or_default();
                                                let response = SyncResponse::SnapshotChunk { data: chunk_data };
                                                let _ = swarm.behaviour_mut().req_resp.send_response(channel, response);
                                            }   
                                            SyncRequest::GetMempoolTxHashes => {
                                                let hashes = mempool.get_all_hashes();
                                                let response = SyncResponse::MempoolTxHashes(hashes);
                                                let _ = swarm.behaviour_mut().req_resp.send_response(channel, response);
                                            }
                                            SyncRequest::GetTxsByHash(hashes) => {
                                                let txs = mempool.get_transactions_by_hashes(&hashes);
                                                let response = SyncResponse::TxsByHash(txs);
                                                let _ = swarm.behaviour_mut().req_resp.send_response(channel, response);
                                            }
                                        }
                                    }
                                    request_response::Message::Response { response, .. } => {
                                        match response {
                                            SyncResponse::TxsByHash(txs) => {
                                                if !txs.is_empty() {
                                                    info!("MEMPOOL_SYNC: Menerima {} transaksi baru dari peer {}.", txs.len(), peer);
                                                    let chain = blockchain.lock().unwrap();
                                                    for tx in txs {
                                                        // Gunakan add_transaction untuk validasi penuh
                                                        if let Err(e) = mempool.add_transaction(tx, &peer.to_string(), &chain.state, &chain) {
                                                            warn!("MEMPOOL_SYNC: Transaksi dari peer {} ditolak: {}", peer, e);
                                                        }
                                                    }
                                                }
                                            }
                                            // Kirim response lain ke Sync Manager
                                            _ => {
                                                if tx_sync_resp.send(response).is_err() {
                                                    error!("P2P: Gagal mengirim respons ke Sync Manager. Channel mungkin tertutup.");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
