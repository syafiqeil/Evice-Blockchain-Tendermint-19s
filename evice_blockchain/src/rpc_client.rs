// src/rpc_client.rs

use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::serde_as;
use thiserror::Error;
use tonic::transport::{Channel, Endpoint};
use rpc_proto::{
    AccountInfoRequest, BlockByIndexRequest,
    TransactionRequest, L2StateRootRequest,
    rpc_service_client::RpcServiceClient,
};

use evice_core::{Leaf, MerkleTreeConfig};
use crate::{Address, Transaction};
use crate::blockchain::Block;
use crate::serde_helpers;

pub struct AccountInfo {
    pub balance: u64,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize)]
struct JsonRpcRequest<T> {
    id: u64,
    jsonrpc: String,
    method: String,
    params: T,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonRpcResponse<T> {
    id: u64,
    jsonrpc: String,
    result: Option<T>,
    error: Option<JsonRpcErrorDetail>,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonRpcErrorDetail {
    code: i64,
    message: String,
}

pub mod rpc_proto {
    tonic::include_proto!("rpc");
}

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),
    #[error("HTTP request error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

#[serde_as]
#[derive(serde::Deserialize, Debug)]
pub struct MerkleProofResponse {
    #[serde_as(as = "serde_helpers::ArkFrArray<2>")]
    pub leaf_data: Leaf,
    #[serde_as(as = "serde_helpers::ArkPath")]
    pub merkle_path: ark_crypto_primitives::merkle_tree::Path<MerkleTreeConfig>,
}

#[derive(Clone)]
pub struct RpcClient {
    // Klien gRPC untuk L1
    l1_client: RpcServiceClient<Channel>,
    // Klien HTTP untuk L2 (Sequencer)
    l2_client: reqwest::Client,
    l2_url: String,
}

impl RpcClient {
    pub async fn new(l1_url: String, l2_url: String) -> Result<Self, RpcError> {
        // --- Setup Klien L1 (gRPC) ---
        let l1_endpoint = Endpoint::from_shared(l1_url.clone())?
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .domain_name("localhost")
                    .ca_certificate(
                        tonic::transport::Certificate::from_pem(tokio::fs::read("ca.pem").await.unwrap())
                    )
            )?;
        let l1_client = RpcServiceClient::connect(l1_endpoint).await?;

        // --- Setup Klien L2 (HTTP) ---
        let l2_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Gagal membuat klien L2");
            
        Ok(Self { l1_client, l2_client, l2_url })
    }

    pub async fn submit_l1_transaction(&mut self, tx: &Transaction) -> Result<String, RpcError> {
        let tx_data = bincode::serialize(tx).expect("Gagal serialize transaksi");

        let request = tonic::Request::new(TransactionRequest {
            transaction_data: tx_data,
        });

        let response = self.l1_client.submit_transaction(request).await?.into_inner();

        if response.success {
            Ok(response.transaction_hash)
        } else {
            Err(RpcError::Grpc(tonic::Status::new(
                tonic::Code::Aborted,
                response.error_message,
            )))
        }
    }

    pub async fn get_l1_account_info(&mut self, address: Address) -> Result<AccountInfo, RpcError> {
        let request = tonic::Request::new(AccountInfoRequest {
            address: address.0.to_vec(),
        });

        let response = self.l1_client.get_account_info(request).await?.into_inner();
        Ok(AccountInfo {
            balance: response.balance,
            nonce: response.nonce,
        })
    }

    pub async fn get_block_by_index(&mut self, index: u64) -> Result<Block, RpcError> {
        let request = tonic::Request::new(BlockByIndexRequest { index });

        let response = self.l1_client.get_block_by_index(request).await?.into_inner();
        let block: Block = bincode::deserialize(&response.block_data)
            .map_err(|e| RpcError::Grpc(tonic::Status::internal(format!("Failed to deserialize block: {}", e))))?;
        Ok(block)
    }

    pub async fn get_l2_state_root(&mut self) -> Result<String, RpcError> {
        let request = tonic::Request::new(L2StateRootRequest {});
        let response = self.l1_client.get_l2_state_root(request).await?.into_inner();
        Ok(hex::encode(&response.state_root))
    }


    // --- FUNGSI-FUNGSI L2 (menggunakan HTTP/JSON) ---
    pub async fn submit_l2_transaction(&self, tx_data: serde_json::Value) -> Result<String, RpcError> {
        let response_text = self.l2_client.post(format!("{}/l2_sendTransaction", self.l2_url))
            .json(&tx_data)
            .send()
            .await?
            .text()
            .await?;
        Ok(response_text)
    }

    pub async fn get_l2_merkle_proof(&self, address: Address, l2_root_hex: &str) -> Result<MerkleProofResponse, RpcError> {
        let params = json!([hex::encode(address.as_ref()), l2_root_hex]);
        let proof_response = self.l2_client.post(format!("{}/l2_getMerkleProof", self.l2_url))
            .json(&params)
            .send()
            .await?
            .json::<MerkleProofResponse>()
            .await?;
        Ok(proof_response)
    }
}