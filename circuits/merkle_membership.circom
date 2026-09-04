pragma circom 2.1.0;

include "poseidon.circom";
include "mux1.circom";

// merkle_membership.circom
//
// Poseidon Merkle membership proof (README "Circuit Design" section 2).
// Proves a leaf is included in a public Merkle root without revealing which
// leaf, so the issuer can revoke attestations by updating their tree.
//
// The prover supplies:
//   - leaf:       the commitment (Poseidon hash of the attribute set)
//   - path[i]:    sibling hash at level i
//   - indices[i]: 0 if the current node is on the left at level i, 1 if right
//   - root:       public Merkle root to verify against

template MerkleMembership(LEVELS) {
    signal input leaf;
    signal input path[LEVELS];
    signal input indices[LEVELS];
    signal input root;
    signal output is_member;

    component hashers[LEVELS];
    component sel_left[LEVELS];
    component sel_right[LEVELS];

    signal level_hash[LEVELS + 1];
    level_hash[0] <== leaf;

    for (var i = 0; i < LEVELS; i++) {
        // Constrain indices[i] is binary (0 or 1).
        indices[i] * (indices[i] - 1) === 0;

        // When indices[i] = 0: current node is LEFT child, sibling is RIGHT
        // When indices[i] = 1: current node is RIGHT child, sibling is LEFT
        sel_left[i] = Mux1();
        sel_left[i].c[0] <== level_hash[i];
        sel_left[i].c[1] <== path[i];
        sel_left[i].s <== indices[i];

        sel_right[i] = Mux1();
        sel_right[i].c[0] <== path[i];
        sel_right[i].c[1] <== level_hash[i];
        sel_right[i].s <== indices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== sel_left[i].out;
        hashers[i].inputs[1] <== sel_right[i].out;

        level_hash[i + 1] <== hashers[i].out;
    }

    // Constrain recomputed root equals the public root.
    root === level_hash[LEVELS];

    is_member <== 1;
}
