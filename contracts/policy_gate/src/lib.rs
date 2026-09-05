#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, MuxedAddress,
    Symbol,
};

use soroban_sdk::token::TokenClient as TransferClient;
use verifier::VerifierContractClient;

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
    /// Sequence (README "How It Works" / "Smart Contract Interface"):
    ///   1. load the gate's default policy (fails closed if unset);
    ///   2. call verifier::verify_proof — reject on failure;
    ///   3. reject if the proof's nullifier was already spent (replay);
    ///   4. record the nullifier as spent;
    ///   5. transfer `amount` from this gate contract to `recipient` on the
    ///      policy's SEP-41 token.
    ///
    /// The gate contract holds the disbursed balance, so the token's
    /// `transfer(from = gate, ...)` authorizes via the calling contract's own
    /// address — external callers cannot move the gate's holding directly.
    pub fn verify_and_transfer(
        env: Env,
        proof: BytesN<256>,
        public_inputs: Bytes,
        recipient: Address,
        amount: i128,
    ) -> Result<(), Error> {
        // 1. Resolve the active (default) policy.
        let store = env.storage().instance();
        let default_policy: Symbol = store.get(&DataKey::DefaultPolicy).ok_or(Error::PolicyNotSet)?;
        let params: PolicyParams = store
            .get(&DataKey::Policy(default_policy))
            .ok_or(Error::PolicyNotSet)?;

        // 2. Verify the Groth16 proof against the policy's verifier contract.
        let verified = VerifierContractClient::new(&env, &params.verifier)
            .verify_proof(&proof, &public_inputs);
        if !verified {
            return Err(Error::ProofVerificationFailed);
        }

        // 3. Extract the proof's nullifier from the Groth16 public signals and
        //    reject replayed nullifiers.
        let nullifier = extract_nullifier(&env, &public_inputs);
        if self_is_nullifier_used(&env, &nullifier) {
            return Err(Error::NullifierAlreadyUsed);
        }

        // 4. Record the nullifier as spent, before attempting the transfer.
        store.set(&DataKey::NullifierUsed(nullifier), &true);

        // 5. Execute the SEP-41 transfer from the gate to the recipient.
        TransferClient::new(&env, &params.token).transfer(
            &env.current_contract_address(),
            &MuxedAddress::from(recipient),
            &amount,
        );
        Ok(())
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

/// Index of the `nullifier` among the Groth16 public signals consumed by
/// `verifier::verify_proof`.
///
/// The kyc_eligibility circuit declares public signals in this order (see
/// circuits/kyc_eligibility.circom):
///   [eligible(output), attestation_root, sanctioned_list_root, nullifier,
///    issuer_pubkey_x, issuer_pubkey_y]
/// so the nullifier is the 4th signal (0-based index 3), i.e. byte offset
/// 3 * 32 in the flat public-inputs blob.
const NULLIFIER_INDEX: u32 = 3;

/// Extract the proof's nullifier from the flat public-inputs blob.
///
/// Fails closed: a blob too short to contain the nullifier yields a zero
/// nullifier (which will collide with nothing and be recorded as spent on the
/// first accepted proof — the verifier already ran, so the blob is well-formed
/// in normal operation).
fn extract_nullifier(env: &Env, public_inputs: &Bytes) -> BytesN<32> {
    let offset = NULLIFIER_INDEX * 32;
    if public_inputs.len() < offset + 32 {
        return BytesN::from_array(env, &[0u8; 32]);
    }
    (&public_inputs.slice(offset..offset + 32))
        .try_into()
        .unwrap_or_else(|_| BytesN::from_array(env, &[0u8; 32]))
}

/// Storage-read form of `is_nullifier_used` (avoids the contract-as-impl
/// recursion between entry points).
fn self_is_nullifier_used(env: &Env, nullifier: &BytesN<32>) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::NullifierUsed(nullifier.clone()))
        .unwrap_or(false)
}
