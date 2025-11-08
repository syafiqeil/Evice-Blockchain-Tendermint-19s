// contracts/bridge_contract/src/handlers.rs

use crate::state::{BridgeState, STATE_KEY};
use evice_core::{Address, WithdrawalProof};
use evice_contract_sdk::{env, storage};
use evice_contract_sdk::bridge::host::{block_timestamp, native_transfer};

pub fn initialize(daily_limit: u64, owner: Address) {
    // Pastikan hanya bisa diinisialisasi sekali
    if storage::read::<BridgeState>(STATE_KEY).is_some() {
        env::revert("Contract already initialized");
    }
    let initial_state = BridgeState {
        daily_limit,
        owner,
        ..Default::default()
    };
    storage::write(STATE_KEY, &initial_state);
    env::log_message("Bridge initialized");
}

pub fn set_daily_limit(new_limit: u64) {
    let mut state: BridgeState = storage::read(STATE_KEY).expect("Contract not initialized");
    if env::caller().as_ref() != state.owner.as_ref() {
        env::revert("Only owner can set daily limit");
    }
    state.daily_limit = new_limit;
    storage::write(STATE_KEY, &state);
}

pub fn withdraw(amount: u64, proof: WithdrawalProof) {
    let mut state: BridgeState = storage::read(STATE_KEY).expect("Contract not initialized");
    
    if state.processed_l2_roots.contains(&proof.l2_state_root) {
        env::revert("Withdrawal proof already used");
    }
    
    let current_day = block_timestamp() / (1000 * 60 * 60 * 24);
    if current_day > state.last_withdrawal_day {
        state.withdrawn_today = 0;
        state.last_withdrawal_day = current_day;
    }
    if state.withdrawn_today + amount > state.daily_limit {
        env::revert("Exceeds daily withdrawal limit");
    }
    
    native_transfer(&env::caller(), amount);

    state.withdrawn_today += amount;
    state.processed_l2_roots.push(proof.l2_state_root);
    storage::write(STATE_KEY, &state);
    
    let log_msg = alloc::format!("Withdrawal of {} to {:?} successful", amount, env::caller());
    env::log_message(&log_msg);
}