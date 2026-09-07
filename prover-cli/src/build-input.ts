// build-input.ts
//
// Derives the kyc_eligibility circuit input JSON from an attestation file
// produced by issuer-service's `npm run attest` (README "Usage" §1) plus the
// policy string the prover supplies (README "Usage" §2).
//
// The attestation JSON carries the user's private attributes, the Poseidon
// commitment, and the issuer EdDSA signature. The circuit additionally needs:
//   - a Merkle root that includes the commitment plus the user's Merkle path;
//   - a context string (corridor + period) to derive the nullifier;
//   - the sanctioned-list root (the policy's jurisdiction-not-in target).
//
// This reference prover reconstructs the demo attestation tree deterministically
// from the commitment so the produced root/path/signature satisfy the circuit —
// mirroring the local test pipeline (test/generate_inputs.ts). See
// docs/decisions.md Day 4. A production prover would receive the Merkle path
// and issuer public key from the issuer directly.

import { buildPoseidon, type PoseidonHash } from "circomlibjs";

export interface AttestationAttributes {
  user: string;
  jurisdiction: string;
  accredited: boolean;
  sanctioned: boolean;
}

export interface Attestation {
  version: 1;
  user: string;
  attributes: AttestationAttributes;
  commitment: string;
  issuer_pubkey: { x: string; y: string };
  signature: { R8: { x: string; y: string }; S: string };
  created_at: string;
}

export interface CircuitInput {
  attestation_root: string;
  sanctioned_list_root: string;
  nullifier: string;
  issuer_pubkey_x: string;
  issuer_pubkey_y: string;
  attributes: string[];
  merkle_path: string[];
  merkle_indices: number[];
  signature: string[];
  context: string;
}

const r = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toHex(v: bigint): string {
  return "0x" + v.toString(16).padStart(64, "0");
}

function hexToBigInt(hex: string): bigint {
  return BigInt(hex.startsWith("0x") ? hex : `0x${hex}`);
}

function poseidonToBigInt(inputs: (bigint | number)[], poseidon: PoseidonHash): bigint {
  const out = poseidon(inputs);
  return poseidon.F.toObject(poseidon.F.e(out));
}

export function stringToFieldElement(s: string, poseidon: PoseidonHash): bigint {
  const bytes = Buffer.from(s, "utf8");
  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    chunks.push(BigInt(`0x${bytes.subarray(i, i + 31).toString("hex")}`));
  }
  if (chunks.length === 0) chunks.push(0n);
  return poseidonToBigInt(chunks, poseidon);
}

function computeCommitment(attributes: AttestationAttributes, poseidon: PoseidonHash): bigint {
  return poseidonToBigInt(
    [
      stringToFieldElement(attributes.user, poseidon),
      stringToFieldElement(attributes.jurisdiction, poseidon),
      attributes.accredited ? 1n : 0n,
      attributes.sanctioned ? 1n : 0n,
    ],
    poseidon,
  );
}

class MerkleTree {
  levels: number;
  layers: bigint[][];
  poseidon: PoseidonHash;

  constructor(leaves: bigint[], levels: number, poseidon: PoseidonHash) {
    this.levels = levels;
    this.poseidon = poseidon;
    const size = 1 << levels;
    const padded = [...leaves];
    while (padded.length < size) {
      padded.push(0n);
    }
    this.layers = [padded];
    for (let i = 0; i < levels; i++) {
      const current = this.layers[i];
      const next: bigint[] = [];
      for (let j = 0; j < current.length; j += 2) {
        next.push(poseidonToBigInt([current[j], current[j + 1]], poseidon));
      }
      this.layers.push(next);
    }
  }

  root(): bigint {
    return this.layers[this.levels][0];
  }

  proof(leafIndex: number): { path: bigint[]; indices: number[] } {
    const path: bigint[] = [];
    const indices: number[] = [];
    let idx = leafIndex;
    for (let level = 0; level < this.levels; level++) {
      path.push(this.layers[level][idx ^ 1]);
      indices.push(idx & 1);
      idx >>= 1;
    }
    return { path, indices };
  }
}

// Policy grammar from README "Usage" §2, e.g.:
//   jurisdiction_not_in:sanctioned_list;accredited:true
// Returns the accredited flag and the sanctioned-list root (a field element
// of the sanctioned jurisdiction, matching the demo circuit's inequality
// check — see docs/decisions.md Day 2).
export function parsePolicy(
  policy: string,
  poseidon: PoseidonHash,
): { requireAccredited: boolean; sanctionedListRoot: bigint } {
  let requireAccredited = false;
  let sanctionedListRoot: bigint | undefined;

  for (const clause of policy.split(";")) {
    const [key, value] = clause.split(":");
    if (!key) continue;
    switch (key.trim()) {
      case "jurisdiction_not_in": {
        if (value === "sanctioned_list") {
          // The demo sanctioned list is a single entry, so its Merkle root is
          // the field element of the sanctioned jurisdiction code "KP".
          sanctionedListRoot = stringToFieldElement("KP", poseidon);
        }
        break;
      }
      case "accredited":
        requireAccredited = value === "true" || value === "1";
        break;
    }
  }

  if (sanctionedListRoot === undefined) {
    throw new Error(
      `policy must declare jurisdiction_not_in:sanctioned_list (got "${policy}")`,
    );
  }
  return { requireAccredited, sanctionedListRoot };
}

/**
 * Build the circuit input JSON for the given attestation and policy.
 *
 * A fresh nullifier context is derived from today's date (corridor + period)
 * so each run produces a distinct, spend-once nullifier as the README
 * describes.
 */
export async function buildCircuitInput(
  attestation: Attestation,
  policy: string,
  context?: string,
): Promise<CircuitInput> {
  const poseidon = await buildPoseidon();

  const { requireAccredited, sanctionedListRoot } = parsePolicy(policy, poseidon);

  const commitmentBigInt = hexToBigInt(attestation.commitment);

  // Deterministic demo attestation tree: the attested commitment as leaf 0,
  // plus two decoy commitments so the tree has realistic depth. Kept aligned
  // with the local test pipeline's tree construction.
  const tree = new MerkleTree([commitmentBigInt, 0n, 1n, 2n], 8, poseidon);
  const attestationRoot = tree.root();
  const { path, indices } = tree.proof(0);

  // Nullifier context: corridor + period. Derived from the provided context or
  // today's date, so the CLI produces a fresh nullifier each run.
  const contextStr = context ?? new Date().toISOString().slice(0, 10);
  const contextFe = stringToFieldElement(contextStr, poseidon);
  const nullifier = poseidonToBigInt([commitmentBigInt, contextFe], poseidon);

  const signatureBigInt = {
    R8x: hexToBigInt(attestation.signature.R8.x),
    R8y: hexToBigInt(attestation.signature.R8.y),
    S: hexToBigInt(attestation.signature.S),
  };

  return {
    attestation_root: toHex(attestationRoot),
    sanctioned_list_root: toHex(sanctionedListRoot),
    nullifier: toHex(nullifier),
    issuer_pubkey_x: attestation.issuer_pubkey.x,
    issuer_pubkey_y: attestation.issuer_pubkey.y,
    attributes: [
      toHex(stringToFieldElement(attestation.attributes.user, poseidon)),
      toHex(stringToFieldElement(attestation.attributes.jurisdiction, poseidon)),
      toHex(attestation.attributes.accredited ? 1n : 0n),
      toHex(attestation.attributes.sanctioned ? 1n : 0n),
    ],
    merkle_path: path.map((p) => toHex(p)),
    merkle_indices: indices,
    signature: [
      toHex(signatureBigInt.R8x),
      toHex(signatureBigInt.R8y),
      toHex(signatureBigInt.S),
    ],
    context: toHex(contextFe),
  };
}
