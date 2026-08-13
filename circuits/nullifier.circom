pragma circom 2.1.0;

// nullifier.circom
//
// Deterministic, context-bound replay protection (README "Circuit Design" §4).
// A fresh nullifier is derived from the attestation commitment and a context
// string (e.g. corridor ID + day) so a proof can't be replayed across periods
// without linking separate transactions to the same user.
//
// Day 1: structure only. Day 2: nullifier = Poseidon([commitment, context]).

template Nullifier() {
    signal input commitment;   // issuer's Poseidon commitment to the attribute set
    signal input context;      // public context string (corridor ID + day)
    signal output nullifier;   // deterministic value bound to commitment + context

    // TODO(Day 2): constrain nullifier === Poseidon([commitment, context]).
    // (placeholder constraint so the skeleton is a valid r1cs)
    1 * 1 === 1;
}
