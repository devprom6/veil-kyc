//! Local (non-network) integration test: prove → gate → SEP-41 transfer.
//!
//! Definition of Done (README "Security & Threat Model" / Day 3 brief):
//!   - valid proof + unused nullifier → transfer succeeds;
//!   - same proof replayed → transfer rejected (nullifier reuse);
//!   - invalid proof → transfer rejected (and nullifier not recorded).
//!
//! `policy_gate` calls the verifier contract by address, so a tiny mock
//! verifier with the same `verify_proof` signature stands in for the real
//! Groth16 pipeline (unit-tested in circuits/ on Day 2); the token is the
//! real SEP-41 `stablecoin_demo`. Everything runs inside one test Env —
//! no live network.

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{
    contract, contractimpl, contracttype, Address, Bytes as SdkBytes, BytesN, Env, String, Symbol,
};
use policy_gate::{Error, PolicyGate, PolicyGateClient, PolicyParams};
use stablecoin_demo::{StablecoinDemo, StablecoinDemoClient};

/// Marker result of a mock verification, keyed like the real verifier.
#[contracttype]
enum MockDataKey {
    Verdict,
}

/// Stand-in for `verifier::verify_proof` wired to a configurable verdict so
/// the gate logic can be exercised without a proving pipeline.
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

/// Groth16 public signals for kyc_eligibility in circuit order:
/// [eligible, attestation_root, sanctioned_list_root, nullifier,
///  issuer_pubkey_x, issuer_pubkey_y]. The 4th slot (index 3) is the
/// nullifier.
fn public_inputs(env: &Env, nullifier: [u8; 32]) -> SdkBytes {
    let mut arr = [0u8; 6 * 32];
    arr[3 * 32..4 * 32].copy_from_slice(&nullifier);
    SdkBytes::from_array(env, &arr)
}

fn fixed_nullifier(n: u8) -> [u8; 32] {
    let mut b = [0xC0; 32];
    b[0] ^= n;
    b
}

/// env, verifier_id, token_id, gate_id
fn setup() -> (Env, Address, Address, Address) {
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
    PolicyGateClient::new(&env, &gate_id)
        .set_policy(&admin, &Symbol::new(&env, "USDC_NG"), &params);

    (env, verifier_id, token_id, gate_id)
}

#[test]
fn valid_proof_unused_nullifier_transfers() {
    let (env, _verifier_id, token_id, gate_id) = setup();
    let recipient = Address::generate(&env);
    let gate = PolicyGateClient::new(&env, &gate_id);
    let token = StablecoinDemoClient::new(&env, &token_id);

    let proof = BytesN::from_array(&env, &[1u8; 256]);
    let inputs = public_inputs(&env, fixed_nullifier(1));

    assert_eq!(gate.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128), Ok(Ok(())));
    assert_eq!(token.balance(&recipient), 100);
    assert_eq!(token.balance(&gate_id), 900);
}

#[test]
fn same_proof_replayed_rejected() {
    let (env, _verifier_id, token_id, gate_id) = setup();
    let recipient = Address::generate(&env);
    let gate = PolicyGateClient::new(&env, &gate_id);
    let token = StablecoinDemoClient::new(&env, &token_id);

    let proof = BytesN::from_array(&env, &[1u8; 256]);
    let inputs = public_inputs(&env, fixed_nullifier(1));

    assert_eq!(gate.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128), Ok(Ok(())));
    // Replay of the identical proof (same nullifier) must fail closed.
    let replay = gate.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128);
    assert_eq!(replay, Err(Ok(Error::NullifierAlreadyUsed)));

    assert_eq!(token.balance(&recipient), 100);
    assert_eq!(token.balance(&gate_id), 900);
}

#[test]
fn invalid_proof_rejected() {
    let (env, verifier_id, token_id, gate_id) = setup();
    let recipient = Address::generate(&env);
    let gate = PolicyGateClient::new(&env, &gate_id);
    let token = StablecoinDemoClient::new(&env, &token_id);

    MockVerifierClient::new(&env, &verifier_id).set_result(&false);
    let proof = BytesN::from_array(&env, &[0u8; 256]);
    let inputs = public_inputs(&env, fixed_nullifier(2));

    let res = gate.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128);
    assert_eq!(res, Err(Ok(Error::ProofVerificationFailed)));

    // Nothing moved, and the nullifier was NOT recorded (still spendable by a
    // later, genuinely valid proof).
    assert_eq!(token.balance(&recipient), 0);
    assert_eq!(token.balance(&gate_id), 1000);
    assert!(!gate.is_nullifier_used(&BytesN::from_array(&env, &fixed_nullifier(2))));
}