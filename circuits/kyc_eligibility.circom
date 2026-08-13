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
// Public inputs: policy_root, sanctioned_list_root, nullifier, issuer_pubkey
// Private inputs: attributes, merkle_path, signature
// Output: eligible (0/1) — the only thing revealed on-chain.
//
// Day 1: declared input/output signatures only. Each enforcement step below
// is a clearly marked TODO for Day 2 — no policy logic yet.

// Enabled on Day 2 when the enforcement components are implemented:
//   include "./merkle_membership.circom";
//   include "./nullifier.circom";

// Array sizes (placeholder — see docs/decisions.md):
//   attributes = [user, jurisdiction, accredited, sanctioned]
//   merkle_path has one sibling hash per level of the issuer attestation tree
//   signature = [R.x, R.y, S] of the BabyJubJub EdDSA signature
template KYCEligibility() {
    // --- public inputs (README "Circuit Design") ---
    signal input policy_root;            // root of the public policy parameters
    signal input sanctioned_list_root;   // Merkle root of sanctioned jurisdictions
    signal input nullifier;              // context-bound, prevents replay
    signal input issuer_pubkey;          // expected issuer public key

    // --- private inputs ---
    signal input attributes[4];      // attribute values A (user, jurisdiction, accredited, sanctioned)
    signal input merkle_path[8];     // sibling hashes along the commitment leaf's path
    signal input signature[3];       // EdDSA σ = (R.x, R.y, S) over commit(A)

    // --- public output ---
    signal output eligible;          // 1 if A satisfies P and σ is valid, else 0

    // --- Day 2 TODOs ---
    // 1. Signature check: σ valid over the Poseidon hash of the attribute set.
    // 2. Merkle membership: commit(A) is a leaf in the issuer's attestation tree.
    // 3. Policy satisfaction: A matches policy_root / sanctioned_list_root.
    // 4. Nullifier: bind nullifier to this attestation + context; set eligible.
    // (placeholder constraint so the skeleton is a valid r1cs)
    1 * 1 === 1;
}

component main {public [policy_root, sanctioned_list_root, nullifier, issuer_pubkey]} = KYCEligibility();
