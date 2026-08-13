#![no_std]

use soroban_sdk::{contract, contractimpl, contracterror, contracttype, Address, BytesN, Env, Symbol, Vec};

/// Corridor/asset-specific eligibility policy (README "Smart Contract
/// Interface"). Provisional shape — finalized when the policy logic lands
/// (Days 2-3).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyParams {
    /// Merkle root of the public sanctioned-jurisdictions list (a public
    /// circuit input).
    pub sanctioned_list_root: BytesN<32>,
    /// Whether this corridor requires accredited-investor status.
    pub require_accredited: bool,
}

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    ProofVerificationFailed = 1,
    NullifierAlreadyUsed = 2,
    NotAuthorized = 3,
}

/// Policy gate that verifies an eligibility proof before allowing a transfer
/// (README "Smart Contract Interface").
///
/// Day 1: interface stubs only — no policy logic yet. All functions fail
/// closed so nothing can be gated open by accident.
#[contract]
pub struct PolicyGate;

#[contractimpl]
impl PolicyGate {
    /// Register a policy for a corridor/asset.
    ///
    /// TODO(Day 3): admin auth + policy storage.
    #[allow(unused_variables)]
    pub fn set_policy(env: Env, admin: Address, policy_id: Symbol, params: PolicyParams) {
        // TODO(Day 3): store policy params under DataKey::Policy(policy_id).
    }

    /// Verify a proof, check the nullifier hasn't been spent for this policy
    /// context, record it, and only then invoke the underlying SEP-41 token
    /// transfer.
    ///
    /// TODO(Day 2-3): call verifier::verify_proof, nullifier tracking, token
    /// transfer. Stub fails closed.
    #[allow(unused_variables)]
    pub fn verify_and_transfer(
        env: Env,
        proof: BytesN<256>,
        public_inputs: Vec<BytesN<32>>,
        recipient: Address,
        amount: i128,
    ) -> Result<(), Error> {
        Err(Error::ProofVerificationFailed)
    }

    /// Whether the given nullifier has already been spent in this policy
    /// context.
    ///
    /// TODO(Day 3): nullifier storage.
    #[allow(unused_variables)]
    pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        false
    }
}
