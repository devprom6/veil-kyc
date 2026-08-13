#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, String, Symbol};

/// Example SEP-41 token gated by policy_gate (README "Repo Structure").
///
/// Day 1: interface stub only. Full SEP-41 implementation and policy-gated
/// transfer land on Day 3.
#[contract]
pub struct StablecoinDemo;

#[contractimpl]
impl StablecoinDemo {
    /// Initialize the token.
    ///
    /// TODO(Day 3): SEP-41 storage (balances, metadata) + policy_gate wiring.
    #[allow(unused_variables)]
    pub fn initialize(env: Env, admin: Address, name: String, symbol: Symbol) {
        // TODO(Day 3): store admin and metadata; enforce admin-only mint.
    }
}
