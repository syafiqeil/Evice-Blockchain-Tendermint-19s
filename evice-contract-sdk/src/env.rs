// evice-contract-sdk/src/env.rs

use crate::{bridge, Address};

// Mengembalikan alamat dari akun yang memanggil kontrak saat ini
pub fn caller() -> Address {
    bridge::host::caller()
}

// Mengembalikan data output ke pemanggil.
pub fn return_data(data: &[u8]) {
    bridge::host::return_data(data);
}

// Mencatat pesan (event) ke log transaksi.
pub fn log_message(message: &str) {
    bridge::host::log_message(message);
}

// Menghentikan eksekusi dan mengembalikan perubahan state, dengan pesan error.
#[inline]
pub fn revert(message: &str) {
    bridge::host::revert(message);
}
