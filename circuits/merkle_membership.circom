pragma circom 2.1.0;

// merkle_membership.circom
//
// Poseidon Merkle membership proof (README "Circuit Design" §2). Proves a leaf
// is included in a public Merkle root without revealing which leaf, so the
// issuer can revoke attestations by updating their tree.
//
// Day 1: structure only. Day 2: hash the leaf up through the path and
// constrain the recomputed root to equal the public root.

template MerkleMembership(LEVELS) {
    signal input leaf;          // Poseidon hash of the attested attribute set
    signal input path[LEVELS];  // sibling hashes, one per level
    signal input root;          // public Merkle root
    signal output is_member;    // 1 if leaf is in the tree rooted at root

    // TODO(Day 2): recompute root from leaf + path; assert root === recomputed.
    // (placeholder constraint so the skeleton is a valid r1cs)
    1 * 1 === 1;
}
