// test/generate_inputs.ts
//
// Generates valid and invalid circuit inputs for kyc_eligibility.circom.
// Uses circomlibjs to compute Poseidon hashes and EdDSA signatures so
// the inputs are consistent with the circuit's constraints.
//
// Usage:
//   npx tsx test/generate_inputs.ts

import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildEddsa, buildPoseidon, type PoseidonHash } from "circomlibjs";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CircuitInput {
  // Public inputs
  attestation_root: string;
  sanctioned_list_root: string;
  nullifier: string;
  issuer_pubkey_x: string;
  issuer_pubkey_y: string;
  // Private inputs
  attributes: string[];
  merkle_path: string[];
  merkle_indices: number[];
  signature: string[];
  context: string;
}

// ---------------------------------------------------------------------------
// Field element helpers
// ---------------------------------------------------------------------------

const BN254_FIELD_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toHex(v: bigint): string {
  return "0x" + v.toString(16).padStart(64, "0");
}

function poseidonToBigInt(inputs: (bigint | number)[], poseidon: PoseidonHash): bigint {
  const out = poseidon(inputs);
  return poseidon.F.toObject(poseidon.F.e(out));
}

function stringToFieldElement(s: string, poseidon: PoseidonHash): bigint {
  const bytes = Buffer.from(s, "utf8");
  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    chunks.push(BigInt(`0x${bytes.subarray(i, i + 31).toString("hex")}`));
  }
  if (chunks.length === 0) chunks.push(0n);
  return poseidonToBigInt(chunks, poseidon);
}

// ---------------------------------------------------------------------------
// Simple Poseidon Merkle tree
// ---------------------------------------------------------------------------

class MerkleTree {
  leaves: bigint[];
  levels: number;
  layers: bigint[][];
  poseidon: PoseidonHash;

  private constructor(leaves: bigint[], levels: number, poseidon: PoseidonHash) {
    this.levels = levels;
    this.poseidon = poseidon;
    const size = 1 << levels;
    this.leaves = [...leaves];
    while (this.leaves.length < size) {
      this.leaves.push(0n);
    }
    this.layers = [];
    this.build();
  }

  private build() {
    let current = this.leaves;
    this.layers = [current];

    for (let i = 0; i < this.levels; i++) {
      const next: bigint[] = [];
      for (let j = 0; j < current.length; j += 2) {
        const left = current[j];
        const right = current[j + 1];
        // Poseidon hash of (left, right) — matches our MerkleMembership circuit
        const hash = poseidonToBigInt([left, right], this.poseidon);
        next.push(hash);
      }
      current = next;
      this.layers.push(current);
    }
  }

  static async create(leaves: bigint[], levels: number): Promise<MerkleTree> {
    const poseidon = await buildPoseidon();
    return new MerkleTree(leaves, levels, poseidon);
  }

  root(): bigint {
    return this.layers[this.levels][0];
  }

  proof(leafIndex: number): { path: bigint[]; indices: number[] } {
    const path: bigint[] = [];
    const indices: number[] = [];
    let idx = leafIndex;

    for (let level = 0; level < this.levels; level++) {
      const siblingIdx = idx ^ 1; // flip last bit
      path.push(this.layers[level][siblingIdx]);
      indices.push(idx & 1);
      idx = idx >> 1;
    }

    return { path, indices };
  }

}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();

  // --- Issuer setup ---
  const issuerPrivateKey = randomBytes(32);
  const issuerPubkey = eddsa.prv2pub(issuerPrivateKey);
  const issuerPubkeyX = eddsa.F.toObject(issuerPubkey[0]);
  const issuerPubkeyY = eddsa.F.toObject(issuerPubkey[1]);

  // --- Sanctioned list (single entry for demo) ---
  const sanctionedJurisdiction = "KP"; // North Korea — universally sanctioned
  const sanctionedFe = stringToFieldElement(sanctionedJurisdiction, poseidon);
  // For a single-entry Merkle tree, the root is just Poseidon(leaf)
  // For the simplified jurisdiction check, the "sanctioned list root" is
  // the field element of the sanctioned jurisdiction itself.  When a user's
  // jurisdiction equals this value, the circuit's inequality check fails.
  // NOTE: this is a demo simplification; see docs/decisions.md.
  const sanctionedRoot = sanctionedFe;

  // --- Create attestation tree with some leaves ---
  const attestations = [
    { user: "alice", jurisdiction: "NG", accredited: true, sanctioned: false },
    { user: "bob", jurisdiction: "US", accredited: true, sanctioned: false },
    { user: "carol", jurisdiction: "GB", accredited: false, sanctioned: false },
    { user: "dave", jurisdiction: "NG", accredited: true, sanctioned: false },
  ];

  const commitments: bigint[] = [];
  for (const att of attestations) {
    const userFe = stringToFieldElement(att.user, poseidon);
    const jurisdictionFe = stringToFieldElement(att.jurisdiction, poseidon);
    const accreditedFe = att.accredited ? 1n : 0n;
    const sanctionedFe2 = att.sanctioned ? 1n : 0n;
    const commitment = poseidonToBigInt([userFe, jurisdictionFe, accreditedFe, sanctionedFe2], poseidon);
    commitments.push(commitment);
  }

  // Build Merkle tree (8 levels)
  const tree = await MerkleTree.create(commitments, 8);
  const attestationRoot = tree.root();

  // --- Generate attestation signature for "alice" (index 0) ---
  const aliceCommitment = commitments[0];
  const signature = eddsa.signPoseidon(issuerPrivateKey, eddsa.F.e(aliceCommitment));

  // --- Merkle proof for alice ---
  const { path, indices } = tree.proof(0);

  // --- Context string (corridor + day) ---
  const context = "USDC-NG-2026-01-15";
  const contextFe = stringToFieldElement(context, poseidon);

  // --- Nullifier ---
  const nullifier = poseidonToBigInt([aliceCommitment, contextFe], poseidon);

  // --- Valid input ---
  const validInput: CircuitInput = {
    // Public
    attestation_root: toHex(attestationRoot),
    sanctioned_list_root: toHex(sanctionedRoot),
    nullifier: toHex(nullifier),
    issuer_pubkey_x: toHex(issuerPubkeyX),
    issuer_pubkey_y: toHex(issuerPubkeyY),
    // Private
    attributes: [
      toHex(stringToFieldElement("alice", poseidon)),
      toHex(stringToFieldElement("NG", poseidon)),
      "0x0000000000000000000000000000000000000000000000000000000000000001", // accredited = 1
      "0x0000000000000000000000000000000000000000000000000000000000000000", // sanctioned = 0
    ],
    merkle_path: path.map((p) => toHex(p)),
    merkle_indices: indices,
    signature: [
      toHex(eddsa.F.toObject(signature.R8[0])),
      toHex(eddsa.F.toObject(signature.R8[1])),
      toHex(signature.S),
    ],
    context: toHex(contextFe),
  };

  // --- Invalid input: accredited = 0 (should fail) ---
  const invalidInput: CircuitInput = {
    ...validInput,
    attributes: [
      validInput.attributes[0],
      validInput.attributes[1],
      "0x0000000000000000000000000000000000000000000000000000000000000000", // accredited = 0
      validInput.attributes[3],
    ],
  };

  // --- Invalid input: wrong signature (should fail) ---
  const wrongSigInput: CircuitInput = {
    ...validInput,
    signature: [
      toHex(eddsa.F.toObject(signature.R8[0])),
      toHex(eddsa.F.toObject(signature.R8[1])),
      toHex((signature.S + 1n) % BN254_FIELD_ORDER), // tampered S
    ],
  };

  // --- Invalid input: sanctioned jurisdiction (KP) trying to prove eligibility ---
  const kpFe = stringToFieldElement("KP", poseidon);
  const kpCommitment = poseidonToBigInt(
    [kpFe, kpFe, 1n, 0n],
    poseidon,
  );
  // Sign the KP commitment
  const kpSignature = eddsa.signPoseidon(issuerPrivateKey, eddsa.F.e(kpCommitment));
  // Add KP to the tree at index 4
  const allCommitments = [...commitments, kpCommitment];
  const kpTree = await MerkleTree.create(allCommitments, 8);
  const kpPath = kpTree.proof(4);
  const kpNullifier = poseidonToBigInt([kpCommitment, contextFe], poseidon);

  const sanctionedInput: CircuitInput = {
    attestation_root: toHex(kpTree.root()),
    sanctioned_list_root: toHex(sanctionedRoot),
    nullifier: toHex(kpNullifier),
    issuer_pubkey_x: toHex(issuerPubkeyX),
    issuer_pubkey_y: toHex(issuerPubkeyY),
    attributes: [
      toHex(kpFe),   // user
      toHex(kpFe),   // jurisdiction = "KP" (sanctioned!)
      "0x0000000000000000000000000000000000000000000000000000000000000001",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    merkle_path: kpPath.path.map((p) => toHex(p)),
    merkle_indices: kpPath.indices,
    signature: [
      toHex(eddsa.F.toObject(kpSignature.R8[0])),
      toHex(eddsa.F.toObject(kpSignature.R8[1])),
      toHex(kpSignature.S),
    ],
    context: toHex(contextFe),
  };

  // --- Write files ---
  const outDir = join(import.meta.dirname ?? ".", "circuit_inputs");
  const { mkdirSync } = await import("node:fs");
  mkdirSync(outDir, { recursive: true });

  writeFileSync(join(outDir, "valid.json"), JSON.stringify(validInput, null, 2) + "\n");
  writeFileSync(join(outDir, "invalid_accredited.json"), JSON.stringify(invalidInput, null, 2) + "\n");
  writeFileSync(join(outDir, "invalid_signature.json"), JSON.stringify(wrongSigInput, null, 2) + "\n");
  writeFileSync(join(outDir, "invalid_sanctioned.json"), JSON.stringify(sanctionedInput, null, 2) + "\n");

  console.log(`[test] wrote 4 input files to ${outDir}/`);
  console.log(`  valid.json              — eligible NG/accredited=true (should pass)`);
  console.log(`  invalid_accredited.json  — accredited=false (should fail at constraint 4a)`);
  console.log(`  invalid_signature.json   — tampered signature (should fail at constraint 2)`);
  console.log(`  invalid_sanctioned.json  — jurisdiction=KP (should fail at constraint 4b)`);
  console.log("");
  console.log(`[test] issuer_pubkey_x = ${toHex(issuerPubkeyX)}`);
  console.log(`[test] issuer_pubkey_y = ${toHex(issuerPubkeyY)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
