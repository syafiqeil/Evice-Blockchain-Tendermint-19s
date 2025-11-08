// evice-contract-sdk/src/lib.rs

#![no_std]
extern crate alloc;

pub mod bridge;
pub mod env;
pub mod storage;

// Ekspor ulang tipe-tipe penting agar mudah diakses
pub type Address = [u8; 20]; 
pub type Balance = u128;