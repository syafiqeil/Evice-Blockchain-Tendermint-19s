// Di dalam src/bin/wallet_generator.rs

use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use keccak_hasher::KeccakHasher;
use hash_db::Hasher;
use evice_blockchain::{
    rpc_client::RpcClient,
    crypto::{KeyPair, ValidatorKeys, ADDRESS_SIZE, public_key_to_address},
    Address, Transaction, TransactionData
};

#[derive(Serialize)]
struct NewWalletInfo {
    address: String,
    private_key: String,
    vrf_public_key: String,
    vrf_secret_key: String,
}

#[derive(Deserialize)]
struct SendTxRequest {
    public_key_hex: String, 
    private_key_hex: String,
    recipient_address_hex: String,
    amount: u64,
    nonce: u64,
}

#[post("/send_transaction")]
async fn send_transaction(req: web::Json<SendTxRequest>) -> impl Responder {
    let l1_rpc_url = "https://127.0.0.1:8080".to_string();
    
    let mut rpc_client = match RpcClient::new(l1_rpc_url, "".to_string()).await {
        Ok(client) => client,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Gagal terhubung ke node: {}", e)),
    };

    // --- PERBAIKAN KRITIS: Rekonstruksi KeyPair menggunakan fungsi dari crypto.rs ---
    let pk_bytes_vec = match hex::decode(&req.public_key_hex) {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::BadRequest().body("Format public key hex tidak valid."),
    };
    let sk_bytes_vec = match hex::decode(&req.private_key_hex) {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::BadRequest().body("Format private key hex tidak valid."),
    };

    let keypair = match KeyPair::from_key_bytes(&pk_bytes_vec, &sk_bytes_vec) {
        Ok(kp) => kp,
        Err(e) => return HttpResponse::BadRequest().body(format!("Gagal membuat keypair: {}", e)),
    };
    let derived_address = public_key_to_address(&keypair.public_key_bytes());
    
    let pk_bytes_vec_as_address = {
        let hash = KeccakHasher::hash(&pk_bytes_vec);
        let mut addr = [0u8; ADDRESS_SIZE];
        addr.copy_from_slice(&hash[hash.len() - ADDRESS_SIZE..]);
        Address(addr)
    };
    
    if derived_address != pk_bytes_vec_as_address {
         return HttpResponse::BadRequest().body("Public key dan private key tidak cocok.");
    }

    // Lanjutkan dengan logika pembuatan transaksi yang sudah benar...
    let recipient_bytes = match hex::decode(&req.recipient_address_hex) {
         Ok(bytes) => bytes,
         Err(_) => return HttpResponse::BadRequest().body("Format recipient address hex tidak valid."),
    };
    let recipient_array: [u8; ADDRESS_SIZE] = match recipient_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return HttpResponse::BadRequest().body(format!("Panjang recipient address salah, harus {} bytes.", ADDRESS_SIZE)),
    };
    let recipient = Address(recipient_array);
    
    let data = TransactionData::Transfer { recipient, amount: req.amount };
    let mut tx = Transaction {
        sender: derived_address,
        data,
        nonce: req.nonce,
        max_fee_per_gas: 20,
        max_priority_fee_per_gas: 2,
        signature: [0; evice_blockchain::crypto::SIGNATURE_SIZE],
    };
    tx.signature = keypair.sign(&tx.message_hash());

    match rpc_client.submit_l1_transaction(&tx).await {
        Ok(tx_hash) => HttpResponse::Ok().json(serde_json::json!({ "status": "sukses", "tx_hash": tx_hash })),
        Err(e) => HttpResponse::InternalServerError().body(format!("Gagal mengirim transaksi: {}", e)),
    }
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Evice Test Wallet Generator</title>
            <style>
                body { font-family: sans-serif; padding: 2em; }
                pre { background-color: #eee; padding: 1em; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }
                button { font-size: 1.2em; padding: 0.5em 1em; }
            </style>
        </head>
        <body>
            <h1>EVICE Test Wallet Generator</h1>
            <button onclick="generateWallet()">Buat Wallet Pengujian Baru</button>
            <div id="walletData"></div>
            <script>
                async function generateWallet() {
                    const response = await fetch('/generate');
                    const data = await response.json();
                    document.getElementById('walletData').innerHTML = `
                        <h2>✅ Wallet Berhasil Dibuat!</h2>
                        <p><strong>Simpan informasi ini baik-baik. Ini akan digunakan untuk proses bootstrap.</strong></p>
                        <pre>
--- Validator ---
Alamat (Sign PubKey): 0x${data.address}
Signing Private Key:  0x${data.private_key}
VRF Public Key:       0x${data.vrf_public_key}
VRF Secret Key:       0x${data.vrf_secret_key}
                        </pre>
                    `;
                }
            </script>
        </body>
        </html>
        "#,
    )
}

#[get("/generate")]
async fn generate_wallet() -> impl Responder {
    // Logika pembuatan kunci dari proyek Anda
    let keys = ValidatorKeys::new();
    
    let wallet_info = NewWalletInfo {
        address: hex::encode(keys.signing_keys.public_key_bytes()),
        private_key: hex::encode(keys.signing_keys.private_key_bytes()),
        vrf_public_key: hex::encode(keys.vrf_keys.public.to_bytes()),
        vrf_secret_key: hex::encode(keys.vrf_keys.secret.to_bytes()),
    };

    HttpResponse::Ok().json(wallet_info)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port = 8000;
    println!("🚀 Wallet Generator berjalan di http://127.0.0.1:{}", port);
    
    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(generate_wallet)
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}