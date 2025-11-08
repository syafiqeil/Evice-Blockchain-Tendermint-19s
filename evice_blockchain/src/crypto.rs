// src/crypto.rs

use pqcrypto_traits::sign::{
    PublicKey as PublicKeyTrait, 
    SecretKey as SecretKeyTrait,
    DetachedSignature as DetachedSignatureTrait,
};
use pqcrypto_dilithium::dilithium2::{
    keypair as dilithium_keypair, detached_sign, verify_detached_signature,
    PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey, DetachedSignature,
    PublicKey,
};
use hash_db::Hasher;
use keccak_hasher::KeccakHasher;
use schnorrkel::{Keypair as SchnorrkelKeypair};

use crate::Address;

// Nilai hardcode yang sudah terverifikasi
pub const PUBLIC_KEY_SIZE: usize = 1312;
pub const ADDRESS_SIZE: usize = 20;
pub const PRIVATE_KEY_SIZE: usize = 2560;
pub const SIGNATURE_SIZE: usize = 2420;

// Menghitung alamat 20-byte dari kunci publik Dilithium 1312-byte.
pub fn public_key_to_address(public_key: &[u8; PUBLIC_KEY_SIZE]) -> Address {
    let hash = KeccakHasher::hash(public_key);
    let mut address_bytes = [0u8; ADDRESS_SIZE];
    address_bytes.copy_from_slice(&hash[hash.len() - ADDRESS_SIZE..]);
    Address(address_bytes)
}

pub struct ValidatorKeys {
    pub signing_keys: KeyPair, 
    pub vrf_keys: SchnorrkelKeypair,
}

impl ValidatorKeys {
    pub fn new() -> Self {
        Self {
            signing_keys: KeyPair::new(),
            vrf_keys: SchnorrkelKeypair::generate(),
        }
    }
}

pub struct KeyPair {
    pub public_key: DilithiumPublicKey,
    pub private_key: DilithiumSecretKey,
}

impl KeyPair {
    pub fn new() -> Self {
        let (pk, sk) = dilithium_keypair();
        Self { public_key: pk, private_key: sk }
    }

    /// Menandatangani pesan menggunakan private key dari keypair.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        let signature = detached_sign(message, &self.private_key);
        signature.as_bytes().try_into().expect("Signature length mismatch")
    }

    /// Mengembalikan public key sebagai array byte.
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.public_key.as_bytes().try_into().expect("Public key length mismatch")
    }

    /// Mengembalikan private key sebagai array byte.
    pub fn private_key_bytes(&self) -> [u8; PRIVATE_KEY_SIZE] {
        self.private_key.as_bytes().try_into().expect("Secret key length mismatch")
    }
    
    pub fn from_key_bytes(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Self, &'static str> {
        let public_key = DilithiumPublicKey::from_bytes(pk_bytes)
            .map_err(|_| "Gagal membuat public key dari bytes: panjang tidak valid")?;
        
        let private_key = DilithiumSecretKey::from_bytes(sk_bytes)
            .map_err(|_| "Gagal membuat secret key dari bytes: panjang tidak valid")?;
        
        Ok(Self { public_key, private_key })
    }
}

/// Fungsi verifikasi global
pub fn verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    if public_key_bytes.len() != PUBLIC_KEY_SIZE {
        return false;
    }
    let pk = match PublicKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match DetachedSignature::from_bytes(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    
    verify_detached_signature(&sig, message, &pk).is_ok()
}

