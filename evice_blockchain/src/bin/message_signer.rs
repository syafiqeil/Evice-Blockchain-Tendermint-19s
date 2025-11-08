use evice_blockchain::crypto::{KeyPair, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE};
use std::env;
use sha2::{Digest, Sha256};

// Utilitas kecil ini menerima kunci privat dan pesan, lalu mencetak tanda tangan.
// Ini memungkinkan skrip bash untuk menghasilkan tanda tangan yang valid.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Penggunaan: message_signer <private_key_hex> <public_key_hex> <message_hex>");
        return Err("Argumen tidak valid".into());
    }

    let sk_hex = &args[1];
    let pk_hex = &args[2];
    let message_hex = &args[3];

    let sk_bytes = hex::decode(sk_hex)?;
    let pk_bytes = hex::decode(pk_hex)?;
    let message_bytes = hex::decode(message_hex)?;

    if sk_bytes.len() != PRIVATE_KEY_SIZE || pk_bytes.len() != PUBLIC_KEY_SIZE {
        return Err("Panjang kunci tidak valid".into());
    }

    let keypair = KeyPair::from_key_bytes(&pk_bytes, &sk_bytes)?;
    let message_hash = Sha256::digest(&message_bytes);
    
    let signature = keypair.sign(&message_hash);
    
    println!("{}", hex::encode(signature));

    Ok(())
}