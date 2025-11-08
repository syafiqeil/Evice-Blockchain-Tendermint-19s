// src/rpc.rs

use crate::{
    blockchain::{Blockchain, ChainMessage},
    mempool::Mempool,
    rpc::rpc_proto::{
        LatestBlocksRequest, LatestBlocksResponse,
        TransactionByHashRequest, TransactionByHashResponse,
    },
    Address, Transaction, snapshot,
};
use tonic::{
    transport::{Server, ServerTlsConfig, Identity},
    Request, Response, Status,
};
use rpc_proto::{
    rpc_service_server::{RpcService, RpcServiceServer},
    AccountInfoRequest, AccountInfoResponse, BlockByIndexRequest, BlockByIndexResponse,
    TransactionRequest, TransactionResponse, CreateSnapshotRequest, CreateSnapshotResponse, 
    L2StateRootRequest, L2StateRootResponse,
};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use tokio::sync::mpsc;
use log::{info, warn, error};

// Kode ini akan dihasilkan secara otomatis oleh build.rs
pub mod rpc_proto {
    tonic::include_proto!("rpc");
}

// Struct yang akan memegang state server kita
pub struct MyRpcServer {
    blockchain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mempool>,
    tx_p2p: mpsc::Sender<ChainMessage>,
    snapshot_dir: PathBuf,
}

// Implementasikan trait layanan gRPC untuk struct kita
#[tonic::async_trait]
impl RpcService for MyRpcServer {
    async fn submit_transaction(
        &self,
        request: Request<TransactionRequest>,
    ) -> Result<Response<TransactionResponse>, Status> {
        let req_data = request.into_inner();

        // Deserialize transaksi dari byte — jangan panic pada deserialization error
        let transaction: Transaction = match bincode::deserialize(&req_data.transaction_data) {
            Ok(tx) => tx,
            Err(e) => {
                warn!("[gRPC] Deserialize transaction failed: {:?}", e);
                return Ok(Response::new(TransactionResponse {
                    success: false,
                    error_message: "Invalid transaction data format".to_string(),
                    transaction_hash: "".to_string(),
                }));
            }
        };

        let tx_hash = hex::encode(transaction.message_hash());

        // Langkah 1: Lakukan semua operasi yang memerlukan lock di dalam blok ini.
        let mempool_result = {
            let chain = self.blockchain.lock().unwrap(); // Lock didapatkan di sini
            self.mempool.add_transaction(
                transaction.clone(),
                "grpc_local",
                &chain.state,
                &chain, // Kirim referensi ke seluruh objek Blockchain
            )
        }; // Lock secara otomatis dilepaskan di sini saat 'chain' keluar dari scope

        match mempool_result {
            Ok(_) => {
                info!("[gRPC] Menerima transaksi valid {}, menyiarkan ke P2P.", tx_hash);
                // .await sekarang aman
                if self.tx_p2p.send(ChainMessage::NewTransaction(transaction)).await.is_err() {
                    error!("[gRPC] Gagal mengirim transaksi ke kanal P2P");
                }
                
                Ok(Response::new(TransactionResponse {
                    success: true,
                    error_message: "".to_string(),
                    transaction_hash: tx_hash,
                }))
            }
            Err(e) => {
                warn!("[gRPC] Menerima transaksi tidak valid: {}", e);
                Ok(Response::new(TransactionResponse {
                    success: false,
                    error_message: e.to_string(),
                    transaction_hash: "".to_string(),
                }))
            }
        }
    }

    async fn create_snapshot(
        &self,
        _request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        info!("[gRPC] Menerima permintaan untuk membuat snapshot.");
        // `try_lock` untuk menghindari deadlock
        let chain = match self.blockchain.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                let msg = "Server sibuk (blockchain terkunci), coba lagi nanti.".to_string();
                warn!("[gRPC] {}", msg);
                return Ok(Response::new(CreateSnapshotResponse { success: false, message: msg }));
            }
        };
        
        let last_block = match chain.chain.last() {
            Some(b) => b,
            None => {
                let msg = "Blockchain kosong, tidak bisa membuat snapshot".to_string();
                warn!("[gRPC] {}", msg);
                return Ok(Response::new(CreateSnapshotResponse { success: false, message: msg }));
            }
        };
        
        let height = last_block.header.index;
        let state_root = chain.state.state_root;
        let db_clone = Arc::clone(&chain.state.db);
        let snapshot_dir_clone = self.snapshot_dir.clone();

        tokio::task::spawn_blocking(move || {
            match snapshot::create_snapshot(db_clone, height, state_root, snapshot_dir_clone) {
                Ok(metadata) => info!("[Snapshot Task] Pembuatan snapshot berhasil dipicu untuk blok #{}", metadata.height),
                Err(e) => error!("[Snapshot Task] Gagal membuat snapshot di background: {:?}", e),
            }
        });

        let msg = "Permintaan pembuatan snapshot diterima dan sedang diproses di background.".to_string();
        Ok(Response::new(CreateSnapshotResponse { success: true, message: msg }))
    }
    
    async fn get_account_info(
        &self,
        request: Request<AccountInfoRequest>,
    ) -> Result<Response<AccountInfoResponse>, Status> {
        let req_data = request.into_inner();
        let address_bytes: [u8; crate::crypto::ADDRESS_SIZE] = req_data.address.try_into()
            .map_err(|_| Status::invalid_argument("Address must be 20 bytes"))?;
        let address = Address(address_bytes);

        let chain = self.blockchain.lock().unwrap();
        let account = chain.state.get_account(&address)
            .map_err(|e| Status::internal(e.to_string()))?
            .unwrap_or_default();
        
        Ok(Response::new(AccountInfoResponse {
            balance: account.balance,
            nonce: account.nonce,
        }))
    }

    async fn get_block_by_index(
        &self,
        request: Request<BlockByIndexRequest>,
    ) -> Result<Response<BlockByIndexResponse>, Status> {
        let req_data = request.into_inner();
        let index = req_data.index;

        let chain = self.blockchain.lock().unwrap();
        
        // Jika index adalah u64::MAX, kembalikan blok terakhir.
        let block_to_get = if index == u64::MAX {
            chain.chain.last()
        } else {
            chain.chain.get(index as usize)
        };

        if let Some(block) = block_to_get {
            let block_data = bincode::serialize(block)
                .map_err(|e| Status::internal(format!("Failed to serialize block: {}", e)))?;
            Ok(Response::new(BlockByIndexResponse { block_data }))
        } else {
            Err(Status::not_found(format!("Block with index {} not found", index)))
        }
    }

    async fn get_l2_state_root(
        &self,
        _request: Request<L2StateRootRequest>,
    ) -> Result<Response<L2StateRootResponse>, Status> {
        let chain = self.blockchain.lock().unwrap();
        let l2_root = chain.state.l2_state_root.clone();

        Ok(Response::new(L2StateRootResponse {
            state_root: l2_root,
        }))
    }
    async fn get_latest_blocks(&self, request: Request<LatestBlocksRequest>) -> Result<Response<LatestBlocksResponse>, Status> {
        let count = request.into_inner().count as usize;
        let chain = self.blockchain.lock().unwrap();
        let blocks_to_send: Vec<Vec<u8>> = chain.chain
            .iter()
            .rev()
            .take(count)
            .filter_map(|block| bincode::serialize(block).ok())
            .collect();
        Ok(Response::new(LatestBlocksResponse { blocks: blocks_to_send }))
    }

    async fn get_transaction_by_hash(
        &self,
        request: Request<TransactionByHashRequest>,
    ) -> Result<Response<TransactionByHashResponse>, Status> {
        let _req_data = request.into_inner();
        
        // TODO: Implementasikan logika sebenarnya di sini.
        // 1. Dapatkan hash dari request.
        // 2. Cari di database (mungkin perlu indeks baru) atau dengan mengiterasi blok.
        // 3. Jika ditemukan, serialisasi dan kirim kembali.
        // 4. Jika tidak, kembalikan error `Status::not_found`.
        
        // Untuk saat ini, kembalikan respons "belum diimplementasikan".
        Err(Status::unimplemented("GetTransactionByHash belum diimplementasikan"))
    }
}

// ===================================================================
//                         Fungsi `run` Server
// ===================================================================
pub async fn run(
    blockchain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mempool>,
    tx_p2p: mpsc::Sender<ChainMessage>,
    port: u16,
    snapshot_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { 
    let addr = format!("0.0.0.0:{}", port).parse()?; 
    let rpc_server = MyRpcServer {
        blockchain,
        mempool,
        tx_p2p,
        snapshot_dir,
    };

    info!("Menjalankan server gRPC di https://{}", addr);

    // --- PERBAIKAN: LOGIKA TLS DIAKTIFKAN ---
    // Muat identitas server (sertifikat dan kunci privat)
    // Pastikan file cert.pem dan key.pem ada di direktori root proyek Anda.
    let cert = tokio::fs::read("cert.pem").await
        .map_err(|e| format!("Gagal membaca cert.pem: {}. Jalankan openssl untuk membuatnya.", e))?;
    let key = tokio::fs::read("key.pem").await
        .map_err(|e| format!("Gagal membaca key.pem: {}. Jalankan openssl untuk membuatnya.", e))?;
    let identity = Identity::from_pem(cert, key);
    let tls_config = ServerTlsConfig::new().identity(identity);
    // ------------------------------------------

    Server::builder()
        .tls_config(tls_config)? // Terapkan konfigurasi TLS
        .add_service(RpcServiceServer::new(rpc_server))
        .serve(addr)
        .await?;

    Ok(())
}