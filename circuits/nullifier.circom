pragma circom 2.1.0;

include "poseidon.circom";

// nullifier.circom
//
// Deterministic, context-bound replay protection (README "Circuit Design"
// section 4). A fresh nullifier is derived from the attestation commitment
// and a context string (e.g. corridor ID + day) so a proof can't be replayed
// across periods without linking separate transactions to the same user.
//
//   nullifier = Poseidon(commitment, context)

template Nullifier() {
    signal input commitment;
    signal input context;
    signal output nullifier;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== commitment;
    hasher.inputs[1] <== context;

    nullifier <== hasher.out;
}
