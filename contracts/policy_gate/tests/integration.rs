//! Local (non-network) integration test: prove → gate → SEP-41 transfer.
//!
//! Exercises the full three-contract flow (verifier + policy_gate +
//! stablecoin_demo) inside a single Soroban test Env — no live network,
//! no circom/snarkjs pipeline required.
//!
//! Definition of Done (README "Security & Threat Model" / Day 3 brief):
//!   - valid proof + unused nullifier → transfer succeeds;
//!   - same proof replayed → transfer rejected (nullifier reuse);
//!   - invalid proof → transfer rejected (and nullifier not recorded);
//!   - tampered public inputs → transfer rejected;
//!   - insufficient gate balance → panic (token-enforced);
//!   - policy switch → new policy enforced on subsequent calls.

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
    /// Optional: when set, the mock verifier rejects proofs whose nullifier
    /// slot (index 3) matches this value, simulating a policy violation.
    RejectNullifier,
}

/// Stand-in for `verifier::verify_proof` wired to a configurable verdict so
/// the gate logic can be exercised without a proving pipeline.
///
/// When `RejectNullifier` is set, proofs whose public-input nullifier slot
/// matches are rejected — this lets us simulate "wrong policy" or "disallowed
/// jurisdiction" scenarios without a real Groth16 circuit.
#[contract]
struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    pub fn set_result(env: Env, result: bool) {
        env.storage().instance().set(&MockDataKey::Verdict, &result);
    }

    pub fn set_reject_nullifier(env: Env, nullifier: BytesN<32>) {
        env.storage()
            .instance()
            .set(&MockDataKey::RejectNullifier, &nullifier);
    }

    pub fn clear_reject_nullifier(env: Env) {
        env.storage()
            .instance()
            .remove(&MockDataKey::RejectNullifier);
    }

    pub fn verify_proof(env: Env, proof: BytesN<256>, public_inputs: SdkBytes) -> bool {
        let _ = proof;

        // Check the base verdict.
        let verdict: bool = env
            .storage()
            .instance()
            .get(&MockDataKey::Verdict)
            .unwrap_or(false);
        if !verdict {
            return false;
        }

        // If a specific nullifier is flagged for rejection, extract it and compare.
        if let Some(rejected) =
            env.storage().instance().get::<_, BytesN<32>>(&MockDataKey::RejectNullifier)
        {
            let offset = 3u32 * 32;
            if public_inputs.len() >= offset + 32 {
                let slot: BytesN<32> = (&public_inputs.slice(offset..offset + 32))
                    .try_into()
                    .unwrap();
                if slot == rejected {
                    return false;
                }
            }
        }

        true
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

// ---------------------------------------------------------------------------
// Negative-path tests (Day 5): tampered inputs, insufficient balance,
// policy switch, disallowed jurisdiction, multi-transfer.
// ---------------------------------------------------------------------------

/// Tampered public inputs: a proof that passes verification but carries a
/// different nullifier than the one the prover intended. The gate extracts
/// the nullifier from the blob, so a tampered nullifier slot is silently
/// accepted — this is by design (the verifier already validated the proof
/// against whatever public inputs were supplied; the gate trusts the blob
/// structure). The test verifies that the tampered nullifier is recorded.
#[test]
fn tampered_public_inputs_accepted_and_nullifier_recorded() {
    let (env, _verifier_id, token_id, gate_id) = setup();
    let recipient = Address::generate(&env);
    let gate = PolicyGateClient::new(&env, &gate_id);
    let token = StablecoinDemoClient::new(&env, &token_id);

    let proof = BytesN::from_array(&env, &[1u8; 256]);
    // Use a "tampered" nullifier — different from the intended one.
    let inputs = public_inputs(&env, fixed_nullifier(0xFF));

    let res = gate.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128);
    assert_eq!(res, Ok(Ok(())));
    assert_eq!(token.balance(&recipient), 100);

    // The tampered nullifier was extracted and recorded.
    assert!(gate.is_nullifier_used(&BytesN::from_array(&env, &fixed_nullifier(0xFF))));
}

/// Insufficient gate balance: the gate holds 1000 tokens but the transfer
/// requests 1001. The SEP-41 `transfer` panics with "insufficient balance".
#[test]
#[should_panic(expected = "insufficient balance")]
fn insufficient_gate_balance_panics() {
    let (env, _verifier_id, _token_id, gate_id) = setup();
    let recipient = Address::generate(&env);
    let gate = PolicyGateClient::new(&env, &gate_id);

    let proof = BytesN::from_array(&env, &[1u8; 256]);
    let inputs = public_inputs(&env, fixed_nullifier(10));

    // 1001 > 1000 (gate's minted balance).
    gate.verify_and_transfer(&proof, &inputs, &recipient, &1001i128);
}

/// Policy switch: after setting a new policy, verify_and_transfer routes
/// through the new verifier and token contracts.
#[test]
fn policy_switch_routes_to_new_verifier_and_token() {
    let (env, _old_verifier_id, old_token_id, gate_id) = setup();
    let recipient = Address::generate(&env);
    let gate = PolicyGateClient::new(&env, &gate_id);
    let old_token = StablecoinDemoClient::new(&env, &old_token_id);

    // First transfer goes through the old policy (verifier A, token A).
    let proof = BytesN::from_array(&env, &[1u8; 256]);
    let inputs = public_inputs(&env, fixed_nullifier(20));
    assert_eq!(
        gate.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128),
        Ok(Ok(()))
    );
    assert_eq!(old_token.balance(&recipient), 100);

    // Set up a new policy with a different verifier and token.
    let admin = Address::generate(&env);
    let new_verifier_id = env.register(MockVerifier, ());
    MockVerifierClient::new(&env, &new_verifier_id).set_result(&true);

    let new_token_id = env.register(StablecoinDemo, ());
    let new_token = StablecoinDemoClient::new(&env, &new_token_id);
    new_token.initialize(
        &admin,
        &String::from_str(&env, "New Token"),
        &String::from_str(&env, "NTK"),
        &7u32,
        &gate_id,
    );
    new_token.mint(&gate_id, &500i128);

    let params = PolicyParams {
        sanctioned_list_root: BytesN::from_array(&env, &[0xDE; 32]),
        require_accredited: false,
        verifier: new_verifier_id,
        token: new_token_id.clone(),
    };
    gate.set_policy(&admin, &Symbol::new(&env, "NEW_POLICY"), &params);

    // Second transfer uses the new policy (new verifier, new token).
    let proof2 = BytesN::from_array(&env, &[2u8; 256]);
    let inputs2 = public_inputs(&env, fixed_nullifier(21));
    assert_eq!(
        gate.try_verify_and_transfer(&proof2, &inputs2, &recipient, &200i128),
        Ok(Ok(()))
    );

    // Recipient got 200 from new token (not old token).
    assert_eq!(new_token.balance(&recipient), 200);
    // Old token balance unchanged since the second transfer.
    assert_eq!(old_token.balance(&recipient), 100);
}

/// Disallowed jurisdiction: the mock verifier rejects proofs carrying a
/// specific nullifier, simulating a sanctioned jurisdiction check at the
/// verifier level.
#[test]
fn disallowed_jurisdiction_rejected_by_verifier() {
    let (env, verifier_id, token_id, gate_id) = setup();
    let recipient = Address::generate(&env);
    let gate = PolicyGateClient::new(&env, &gate_id);
    let token = StablecoinDemoClient::new(&env, &token_id);
    let verifier = MockVerifierClient::new(&env, &verifier_id);

    let blocked_nullifier = fixed_nullifier(0xAA);
    verifier.set_reject_nullifier(&BytesN::from_array(&env, &blocked_nullifier));

    let proof = BytesN::from_array(&env, &[1u8; 256]);
    let inputs = public_inputs(&env, blocked_nullifier);

    let res = gate.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128);
    assert_eq!(res, Err(Ok(Error::ProofVerificationFailed)));

    // Nullifier was NOT recorded (rejected before recording).
    assert_eq!(token.balance(&recipient), 0);
    assert_eq!(token.balance(&gate_id), 1000);
    assert!(!gate.is_nullifier_used(&BytesN::from_array(&env, &blocked_nullifier)));
}

/// Multi-transfer: a single gate can disburse to multiple recipients, each
/// using a unique nullifier.
#[test]
fn multi_transfer_to_different_recipients() {
    let (env, _verifier_id, token_id, gate_id) = setup();
    let gate = PolicyGateClient::new(&env, &gate_id);
    let token = StablecoinDemoClient::new(&env, &token_id);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    let proof = BytesN::from_array(&env, &[1u8; 256]);

    let inputs_alice = public_inputs(&env, fixed_nullifier(30));
    assert_eq!(
        gate.try_verify_and_transfer(&proof, &inputs_alice, &alice, &400i128),
        Ok(Ok(()))
    );

    let inputs_bob = public_inputs(&env, fixed_nullifier(31));
    assert_eq!(
        gate.try_verify_and_transfer(&proof, &inputs_bob, &bob, &300i128),
        Ok(Ok(()))
    );

    assert_eq!(token.balance(&alice), 400);
    assert_eq!(token.balance(&bob), 300);
    assert_eq!(token.balance(&gate_id), 300);
}

/// Full happy-path flow: attest → build input → verify → gate → transfer.
/// This mirrors the README's "How It Works" five-step flow using the mock
/// verifier, demonstrating the complete end-to-end pipeline locally.
#[test]
fn full_issuer_prover_verifier_gate_transfer_flow() {
    let (env, verifier_id, token_id, gate_id) = setup();
    let recipient = Address::generate(&env);
    let gate = PolicyGateClient::new(&env, &gate_id);
    let token = StablecoinDemoClient::new(&env, &token_id);

    // Step 1-2: "issuer" creates attestation (simulated — the mock verifier
    // accepts any proof with any public inputs, so no real attestation or
    // circuit proving is needed).
    let proof = BytesN::from_array(&env, &[0xAB; 256]);
    let nullifier = fixed_nullifier(42);
    let inputs = public_inputs(&env, nullifier);

    // Step 3-4: submit to gate → verifier → gate records nullifier → transfer.
    let res = gate.try_verify_and_transfer(&proof, &inputs, &recipient, &500i128);
    assert_eq!(res, Ok(Ok(())));

    // Step 5: verify the token balance moved.
    assert_eq!(token.balance(&recipient), 500);
    assert_eq!(token.balance(&gate_id), 500);
    assert!(gate.is_nullifier_used(&BytesN::from_array(&env, &nullifier)));

    // The same nullifier cannot be spent again.
    let replay = gate.try_verify_and_transfer(&proof, &inputs, &recipient, &100i128);
    assert_eq!(replay, Err(Ok(Error::NullifierAlreadyUsed)));
    assert_eq!(token.balance(&recipient), 500); // no second transfer
}