#![no_std]

use soroban_sdk::{contract, contractimpl, BytesN, Env, Vec};

/// Generic, stateless BN254/Poseidon proof verifier (README "Smart Contract
/// Interface"). Any policy contract can plug into it.
///
/// Day 1: stub only — interface is declared, no verification logic yet.
#[contract]
pub struct VerifierContract;

#[contractimpl]
impl VerifierContract {
    /// Verify a Groth16/UltraHonk proof against its public inputs using
    /// Stellar's native BN254 pairing and Poseidon host functions
    /// (Protocol 25 "X-Ray", CAP-79/CAP-75).
    ///
    /// TODO(Day 2): invoke the native host functions and return the
    /// verification outcome. Until then, the stub fails closed.
    #[allow(unused_variables)]
    pub fn verify_proof(
        env: Env,
        proof: BytesN<256>,
        public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{vec, Env};

    #[test]
    fn verify_proof_stub_returns_false() {
        let env = Env::default();
        let proof = BytesN::from_array(&env, &[0u8; 256]);
        let public_inputs = vec![&env, BytesN::from_array(&env, &[0u8; 32])];
        assert!(!VerifierContract::verify_proof(env, proof, public_inputs));
    }
}
