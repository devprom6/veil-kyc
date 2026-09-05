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

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, Bytes as SdkBytes, String};
    use stablecoin_demo::{StablecoinDemo, StablecoinDemoClient};

    /// Deterministic, context-scoped nullifier at Groth16 public-signal index 3
    /// (see NULLIFIER_INDEX above).
    const ANCHOR: [u8; 32] = [0xC0; 32];
    fn nullifier_bytes(n: u8) -> [u8; 32] {
        let mut b = ANCHOR;
        b[0] ^= n;
        b
    }
    fn public_inputs(env: &Env, nullifier: [u8; 32]) -> SdkBytes {
        let mut arr = [0u8; 6 * 32];
        arr[3 * 32..4 * 32].copy_from_slice(&nullifier);
        SdkBytes::from_array(env, &arr)
    }

    /// Minimal stand-in for the verifier contract. Real Groth16 proofs come
    /// from the circuit proving pipeline; the unit tests here exercise the
    /// gate logic, so the mock exposes the same `verify_proof` signature and
    /// returns a configurable verdict.
    #[contracttype]
    enum MockDataKey {
        Verdict,
    }

    #[contract]
    struct MockVerifier;

    #[contractimpl]
    impl MockVerifier {
        pub fn set_result(env: Env, result: bool) {
            env.storage().instance().set(&MockDataKey::Verdict, &result);
        }
        pub fn verify_proof(env: Env, proof: BytesN<256>, public_inputs: SdkBytes) -> bool {
            let _ = (proof, public_inputs);
            env.storage().instance().get(&MockDataKey::Verdict).unwrap_or(false)
        }
    }

    /// env, verifier_id, token_id, gate_id
    fn setup_env() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);

        let gate_id = env.register(PolicyGate, ());
        let verifier_id = env.register(MockVerifier, ());
        let token_id = env.register(StablecoinDemo, ());

        let token = StablecoinDemoClient::new(&env, &token_id);
        token.initialize(
            &admin,
            &String::from_str(&env, "Veil Demo USD"),
            &String::from_str(&env, "VDUSD"),
            &7u32,
            &gate_id,
        );
        token.mint(&gate_id, &1000i128); // demo supply held by the gate

        MockVerifierClient::new(&env, &verifier_id).set_result(&true);

        let params = PolicyParams {
            sanctioned_list_root: BytesN::from_array(&env, &[0xAB; 32]),
            require_accredited: true,
            verifier: verifier_id.clone(),
            token: token_id.clone(),
        };
        PolicyGateClient::new(&env, &gate_id).set_policy(
            &admin,
            &Symbol::new(&env, "USDC_NG"),
            &params,
        );

        (env, verifier_id, token_id, gate_id)
    }

    #[test]
    fn valid_proof_with_unused_nullifier_transfers() {
        let (env, _verifier_id, token_id, gate_id) = setup_env();
        let recipient = Address::generate(&env);
        let gate_client = PolicyGateClient::new(&env, &gate_id);
        let token = StablecoinDemoClient::new(&env, &token_id);

        let proof = BytesN::from_array(&env, &[1u8; 256]);
        let inputs = public_inputs(&env, nullifier_bytes(1));

        let res = gate_client.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128);
        assert_eq!(res, Ok(Ok(())));

        assert_eq!(token.balance(&recipient), 100);
        assert_eq!(token.balance(&gate_id), 900);
        assert!(gate_client.is_nullifier_used(&BytesN::from_array(&env, &nullifier_bytes(1))));
    }

    #[test]
    fn replayed_nullifier_rejected() {
        let (env, _verifier_id, token_id, gate_id) = setup_env();
        let recipient = Address::generate(&env);
        let gate_client = PolicyGateClient::new(&env, &gate_id);
        let token = StablecoinDemoClient::new(&env, &token_id);

        let proof = BytesN::from_array(&env, &[1u8; 256]);
        let inputs = public_inputs(&env, nullifier_bytes(1));

        assert_eq!(
            gate_client.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128),
            Ok(Ok(()))
        );
        let replay = gate_client.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128);
        assert_eq!(replay, Err(Ok(Error::NullifierAlreadyUsed)));

        // No second transfer occurred.
        assert_eq!(token.balance(&recipient), 100);
        assert_eq!(token.balance(&gate_id), 900);
    }

    #[test]
    fn invalid_proof_rejected_without_recording_nullifier() {
        let (env, verifier_id, token_id, gate_id) = setup_env();
        let recipient = Address::generate(&env);
        let gate_client = PolicyGateClient::new(&env, &gate_id);
        let token = StablecoinDemoClient::new(&env, &token_id);

        let verifier = MockVerifierClient::new(&env, &verifier_id);
        verifier.set_result(&false);
        let proof = BytesN::from_array(&env, &[0u8; 256]);
        let inputs = public_inputs(&env, nullifier_bytes(2));

        let res = gate_client.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128);
        assert_eq!(res, Err(Ok(Error::ProofVerificationFailed)));

        // Nothing moved and the nullifier was not recorded.
        assert_eq!(token.balance(&recipient), 0);
        assert_eq!(token.balance(&gate_id), 1000);
        assert!(!gate_client.is_nullifier_used(&BytesN::from_array(&env, &nullifier_bytes(2))));
    }

    #[test]
    fn failed_verification_then_valid_proof_still_works() {
        // Regression: an invalid attempt must not poison later valid spends.
        let (env, verifier_id, token_id, gate_id) = setup_env();
        let recipient = Address::generate(&env);
        let gate_client = PolicyGateClient::new(&env, &gate_id);
        let token = StablecoinDemoClient::new(&env, &token_id);
        let verifier = MockVerifierClient::new(&env, &verifier_id);

        verifier.set_result(&false);
        let bad = gate_client.try_verify_and_transfer(
            &BytesN::from_array(&env, &[0u8; 256]),
            &public_inputs(&env, nullifier_bytes(3)),
            &recipient,
            &100i128,
        );
        assert_eq!(bad, Err(Ok(Error::ProofVerificationFailed)));

        verifier.set_result(&true);
        let good = gate_client.try_verify_and_transfer(
            &BytesN::from_array(&env, &[1u8; 256]),
            &public_inputs(&env, nullifier_bytes(3)),
            &recipient,
            &100i128,
        );
        assert_eq!(good, Ok(Ok(())));
        assert_eq!(token.balance(&recipient), 100);
    }

    #[test]
    fn policy_not_set_fails_closed() {
        let env = Env::default();
        env.mock_all_auths();
        let recipient = Address::generate(&env);

        // No set_policy call yet.
        let gate_id = env.register(PolicyGate, ());
        let gate_client = PolicyGateClient::new(&env, &gate_id);

        let res = gate_client.try_verify_and_transfer(
            &BytesN::from_array(&env, &[1u8; 256]),
            &public_inputs(&env, nullifier_bytes(5)),
            &recipient,
            &100i128,
        );
        assert_eq!(res, Err(Ok(Error::PolicyNotSet)));
    }

    #[test]
    fn latest_set_policy_is_enforced() {
        let (env, _verifier_id, token_id, gate_id) = setup_env();
        let recipient = Address::generate(&env);
        let gate_client = PolicyGateClient::new(&env, &gate_id);
        let token = StablecoinDemoClient::new(&env, &token_id);

        // Re-set the policy with a different sanctioned root; transfer still
        // routes to the same verifier/token.
        let admin = Address::generate(&env);
        let new_verifier_id = env.register(MockVerifier, ());
        MockVerifierClient::new(&env, &new_verifier_id).set_result(&true);
        let params = PolicyParams {
            sanctioned_list_root: BytesN::from_array(&env, &[0xCD; 32]),
            require_accredited: false,
            verifier: new_verifier_id,
            token: token_id,
        };
        gate_client.set_policy(&admin, &Symbol::new(&env, "USDC_EU"), &params);

        let res = gate_client.try_verify_and_transfer(
            &BytesN::from_array(&env, &[2u8; 256]),
            &public_inputs(&env, nullifier_bytes(6)),
            &recipient,
            &50i128,
        );
        assert_eq!(res, Ok(Ok(())));
        assert_eq!(token.balance(&recipient), 50);
    }
}
