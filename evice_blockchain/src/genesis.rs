use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::File, path::Path};

// Merepresentasikan keseluruhan file genesis.json
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Genesis {
    pub genesis_time: u64,
    pub chain_id: String,
    // Menggunakan HashMap agar mudah mencari akun berdasarkan alamat
    pub accounts: HashMap<String, GenesisAccount>,
}

// Merepresentasikan setiap akun di dalam genesis
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisAccount {
    pub balance: String, // Gunakan String untuk angka besar, lebih aman
    pub staked_amount: String,
    // Kunci-kunci penting untuk validator
    pub vrf_public_key: Option<String>,
}

impl Genesis {
    // Fungsi pembantu untuk memuat genesis dari file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let genesis: Self = serde_json::from_reader(file)?;
        Ok(genesis)
    }
}