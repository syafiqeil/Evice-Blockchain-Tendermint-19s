// contracts/fungible_token/src/state.rs

use borsh::{BorshDeserialize, BorshSerialize};
use evice_contract_sdk::Address;
use serde::Serialize;
use alloc::vec::Vec;

// Kunci-kunci penyimpanan yang granular
pub fn balance_key(owner: &Address) -> Vec<u8> { [b"balances/", owner.as_ref()].concat() }
pub fn allowance_key(owner: &Address, spender: &Address) -> Vec<u8> { [b"allowances/", owner.as_ref(), spender.as_ref()].concat() }

// Aksi yang dapat dipanggil oleh pengguna 
#[derive(BorshSerialize, BorshDeserialize)]
pub enum CallAction {
    // Fungsi Tulis
    Transfer { to: Address, amount: u128 },
    Approve { spender: Address, amount: u128 },
    TransferFrom { from: Address, to: Address, amount: u128 },
    
    // Fungsi Baca
    BalanceOf { owner: Address },
    Allowance { owner: Address, spender: Address },
}

// Definisi Event
#[derive(Serialize)]
pub enum Event {
    Transfer { from: Address, to: Address, value: u128 },
    Approval { owner: Address, spender: Address, value: u128 },
}