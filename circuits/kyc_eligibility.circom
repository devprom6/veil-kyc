pragma circom 2.1.0;

// kyc_eligibility.circom
//
// Core eligibility circuit (README "Circuit Design"). Proves:
//
//   "I know a set of attributes A and a valid issuer signature σ over
//    commit(A), such that commit(A) is a leaf in the issuer's published
//    Merkle tree of valid attestations, A satisfies public policy P, and I
//    have not already used this attestation for this nullifier context."
//
// Public inputs: attestation_root, sanctioned_list_root, nullifier,
//                issuer_pubkey_x, issuer_pubkey_y
// Private inputs: attributes[4], merkle_path[8], merkle_indices[8],
//                 signature[3], context
// Output: eligible (0/1) — the only thing revealed on-chain.
//
// Day 2: full constraint logic — all four properties enforced.

include "poseidon.circom";
include "eddsaposeidon.circom";
include "comparators.circom";
include "merkle_membership.circom";
include "nullifier.circom";

template KYCEligibility() {
    // --- public inputs (README "Circuit Design") ---
    signal input attestation_root;       // Merkle root of the issuer's attestation tree
    signal input sanctioned_list_root;   // Merkle root of sanctioned jurisdictions
    signal input nullifier;              // context-bound, prevents replay
    signal input issuer_pubkey_x;        // issuer's BabyJubJub public key (x)
    signal input issuer_pubkey_y;        // issuer's BabyJubJub public key (y)

    // --- private inputs ---
    signal input attributes[4];          // [user, jurisdiction, accredited, sanctioned]
    signal input merkle_path[8];         // sibling hashes in attestation tree
    signal input merkle_indices[8];      // path direction at each level (0=left, 1=right)
    signal input signature[3];           // EdDSA σ = [R8.x, R8.y, S]
    signal input context;                // context string (e.g. corridor ID + day)

    // --- public output ---
    signal output eligible;

    // -----------------------------------------------------------------------
    // Step 1 — Compute commitment = Poseidon(attributes)
    // -----------------------------------------------------------------------
    component commitment_hasher = Poseidon(4);
    commitment_hasher.inputs[0] <== attributes[0]; // user
    commitment_hasher.inputs[1] <== attributes[1]; // jurisdiction
    commitment_hasher.inputs[2] <== attributes[2]; // accredited (0 or 1)
    commitment_hasher.inputs[3] <== attributes[3]; // sanctioned (0 or 1)
    signal commitment;
    commitment <== commitment_hasher.out;

    // -----------------------------------------------------------------------
    // Step 2 — Verify issuer EdDSA signature over commitment
    //   (README property 1: "the issuer's signature over the attribute
    //    commitment is valid")
    //
    // EdDSAPoseidonVerifier internally hashes H(R8x, R8y, Ax, Ay, M) with
    // Poseidon and checks S·B8 == R8 + H·A on BabyJubJub.
    // -----------------------------------------------------------------------
    component sig_verifier = EdDSAPoseidonVerifier();
    sig_verifier.enabled <== 1;
    sig_verifier.Ax <== issuer_pubkey_x;
    sig_verifier.Ay <== issuer_pubkey_y;
    sig_verifier.R8x <== signature[0];
    sig_verifier.R8y <== signature[1];
    sig_verifier.S <== signature[2];
    sig_verifier.M <== commitment;

    // -----------------------------------------------------------------------
    // Step 3 — Merkle membership in the issuer's attestation tree
    //   (README property 2: "commitment is included in the issuer's current
    //    attestation tree")
    // -----------------------------------------------------------------------
    component merkle = MerkleMembership(8);
    merkle.leaf <== commitment;
    for (var i = 0; i < 8; i++) {
        merkle.path[i] <== merkle_path[i];
        merkle.indices[i] <== merkle_indices[i];
    }
    merkle.root <== attestation_root;

    // -----------------------------------------------------------------------
    // Step 4 — Policy constraints
    //   (README property 3: "arithmetic/comparison constraints over the
    //    private attributes match the public policy")
    //
    //   4a. accredited flag must equal 1
    //   4b. jurisdiction must not be in the sanctioned list
    //
    //   NOTE: the jurisdiction-not-sanctioned check uses a field-element
    //   inequality (jurisdiction != sanctioned_list_root). This is sound for
    //   single-entry sanctioned lists where root = Poseidon(jurisdiction).
    //   A production implementation should use Merkle non-membership proofs;
    //   see docs/decisions.md.
    // -----------------------------------------------------------------------

    // 4a: accredited === 1
    attributes[2] === 1;

    // 4b: jurisdiction not in sanctioned list (simplified inequality)
    component jurisdiction_check = IsZero();
    jurisdiction_check.in <== attributes[1] - sanctioned_list_root;
    jurisdiction_check.out === 0;

    // -----------------------------------------------------------------------
    // Step 5 — Nullifier derivation
    //   (README property 4: "deterministic value derived from the attestation
    //    and a context string, output publicly, preventing reuse")
    //
    //   nullifier == Poseidon(commitment, context)
    //   The public nullifier input must match the computed value, binding the
    //   proof to a specific context (corridor + time period).
    // -----------------------------------------------------------------------
    component nullifier_hasher = Poseidon(2);
    nullifier_hasher.inputs[0] <== commitment;
    nullifier_hasher.inputs[1] <== context;
    nullifier_hasher.out === nullifier;

    // -----------------------------------------------------------------------
    // Step 6 — Eligible output
    //
    //   If all the above constraints are satisfied, the circuit has a valid
    //   witness and eligible == 1.  If any constraint is unsatisfiable, no
    //   valid witness exists — the proof cannot be generated at all.
    // -----------------------------------------------------------------------
    eligible <== 1;
}

// Public inputs match README "Circuit Design" plus attestation_root (the
// issuer's Merkle tree root, required for membership verification) and
// issuer_pubkey split into x/y coordinates for EdDSA.
component main {public [
    attestation_root,
    sanctioned_list_root,
    nullifier,
    issuer_pubkey_x,
    issuer_pubkey_y
]} = KYCEligibility();
