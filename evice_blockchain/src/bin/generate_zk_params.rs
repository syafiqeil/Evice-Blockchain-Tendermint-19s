// src/bin/generate_zk_params.rs

use evice_blockchain::l2_circuit::{BatchSystemCircuit, get_poseidon_parameters};

use std::fs::File;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔥 Menghasilkan Proving Key dan Verifying Key untuk Sirkuit L2...");
    
    let poseidon_config = get_poseidon_parameters();
    let dummy_circuit = BatchSystemCircuit {
        initial_root: Fr::default(),
        final_root: Fr::default(),
        transactions: vec![],
        initial_leaves: vec![],
        leaf_crh_params: poseidon_config.clone(),
        two_to_one_crh_params: poseidon_config,
    };

    let mut rng = thread_rng();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit, &mut rng)?;

    // Simpan Proving Key
    let mut pk_file = File::create("proving_key.bin")?;
    pk.serialize_uncompressed(&mut pk_file)?;
    println!("✅ Proving Key berhasil disimpan ke 'proving_key.bin'");

    // Simpan Verifying Key
    let mut vk_file = File::create("verifying_key.bin")?;
    vk.serialize_uncompressed(&mut vk_file)?;
    println!("✅ Verifying Key berhasil disimpan ke 'verifying_key.bin'");

    Ok(())
}

