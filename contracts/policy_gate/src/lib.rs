#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol,
};

/// Corridor/asset-specific eligibility policy (README "Smart Contract
/// Interface"). Set once per corridor/asset by an admin via `set_policy`.
///
/// Beyond the policy parameters from the Day 1 scaffold (`sanctioned_list_root`,
/// `require_accredited`), each policy carries the addresses of the verifier
/// contract to consult for proof verification and the SEP-41 token contract on
/// which `verify_and_transfer` ultimately executes.  This keeps the README's
/// `set_policy`/`verify_and_transfer` entry points unchanged (see
/// docs/decisions.md Day 3).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyParams {
    /// Merkle root of the public sanctioned-jurisdictions list (a public
    /// circuit input).
    pub sanctioned_list_root: BytesN<32>,
    /// Whether this corridor requires accredited-investor status.
    pub require_accredited: bool,
    /// Address of the `verifier` contract whose `verify_proof` this gate calls.
    pub verifier: Address,
    /// Address of the SEP-41 token contract this gate disburses from.
    pub token: Address,
}

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    ProofVerificationFailed = 1,
    NullifierAlreadyUsed = 2,
    NotAuthorized = 3,
    PolicyNotSet = 4,
}

/// Contract instance storage keys.
#[contracttype]
enum DataKey {
    /// Params registered for a given corridor/asset via `set_policy`.
    Policy(Symbol),
    /// Which policy this gate currently enforces (single-default-policy model).
    DefaultPolicy,
    /// Spent-nullifier marker: a nullifier can only be spent once (README
    /// Security & Threat Model — replay mitigation).
    NullifierUsed(BytesN<32>),
}

/// Corridor/asset-specific eligibility policy gate (README "Smart Contract
/// Interface").
///
/// `verify_and_transfer` runs the README gate-then-transfer sequence: call the
/// `verifier` contract's `verify_proof`, reject replayed nullifiers, record the
/// nullifier, and only then invoke the underlying SEP-41 token transfer.
#[contract]
pub struct PolicyGate;

#[contractimpl]
impl PolicyGate {
    /// Register a policy for a corridor/asset. Admin-gated: only the caller
    /// authorized as `admin` may set a policy.
    ///
    /// The most recently set policy becomes the gate's default, which
    /// `verify_and_transfer` enforces (README's `verify_and_transfer` carries
    /// no `policy_id`, so this gate resolves to a single active policy — see
    /// docs/decisions.md Day 3).
    pub fn set_policy(env: Env, admin: Address, policy_id: Symbol, params: PolicyParams) {
        admin.require_auth();
        let store = env.storage().instance();
        store.set(&DataKey::Policy(policy_id.clone()), &params);
        store.set(&DataKey::DefaultPolicy, &policy_id);
    }

    /// Verify a proof, check the nullifier hasn't been spent for this policy
    /// context, record it, and only then invoke the underlying SEP-41 token
    /// transfer.
    ///
    /// TODO(Day 3): call verifier::verify_proof, nullifier tracking, token
    /// transfer. Stub fails closed.
    #[allow(unused_variables)]
    pub fn verify_and_transfer(
        env: Env,
        proof: BytesN<256>,
        public_inputs: Bytes,
        recipient: Address,
        amount: i128,
    ) -> Result<(), Error> {
        Err(Error::ProofVerificationFailed)
    }

    /// Whether the given nullifier has already been spent in this policy
    /// context.
    ///
    /// Nullifiers are bound to a context (corridor + period) inside the
    /// circuit itself (`nullifier == Poseidon(commitment, context)`), so a
    /// spent marker keyed purely by the 32-byte nullifier is context-scoped
    /// by construction.
    pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::NullifierUsed(nullifier))
            .unwrap_or(false)
    }
}
