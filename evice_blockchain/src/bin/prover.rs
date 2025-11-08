// src/bin/prover.rs

use evice_blockchain::l2_circuit::{PoseidonMerkleTreeParams, BatchSystemCircuit};
use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use clap::Parser;
use std::fs::File;

#[derive(Parser, Debug)]
#[clap(name = "prover-cli")]
struct Cli {
    #[clap(long)]
    params_path: String,
    #[clap(long)]
    proving_key_path: String,
    #[clap(long)]
    circuit_data_hex: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut rng = thread_rng();

    // 1. Muat parameter & proving key
    let params_file = File::open(&cli.params_path)?;
    let _params = PoseidonMerkleTreeParams::deserialize_uncompressed(params_file)?;
    let mut pk_file = File::open(&cli.proving_key_path)?;
    let pk = ProvingKey::deserialize_uncompressed_unchecked(&mut pk_file)?;

    // 2. Deserialisasi data sirkuit batch dari argumen hex
    let circuit_data_bytes = hex::decode(cli.circuit_data_hex)?;
    let circuit: BatchSystemCircuit = BatchSystemCircuit::deserialize_uncompressed(&circuit_data_bytes[..])?;

    // 3. Hasilkan bukti ZK untuk seluruh batch
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)?;

    // 4. Cetak bukti ke stdout dalam format hex
    let mut proof_bytes = Vec::new();
    proof.serialize_uncompressed(&mut proof_bytes)?;
    println!("{}", hex::encode(&proof_bytes));

    Ok(())
}