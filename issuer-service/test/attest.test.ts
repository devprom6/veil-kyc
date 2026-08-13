import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import {
  computeCommitment,
  createAttestation,
  hexToBigInt,
  stringToFieldElement,
  type Attestation,
} from "../src/attest.js";

function parseAttestation(att: Attestation) {
  return {
    commitment: hexToBigInt(att.commitment),
    pubkey: [hexToBigInt(att.issuer_pubkey.x), hexToBigInt(att.issuer_pubkey.y)] as const,
    signature: {
      R8: [hexToBigInt(att.signature.R8.x), hexToBigInt(att.signature.R8.y)] as const,
      S: hexToBigInt(att.signature.S),
    },
  };
}

test("createAttestation produces a well-formed, verifiable attestation", async () => {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const privateKey = randomBytes(32);

  const att = await createAttestation({
    user: "GBRLZHGNJ4ST7U3FX4C2QG4LBW2V5PBQFTM5A3X5R6AT4LXKQNLJQHCA",
    jurisdiction: "NG",
    accredited: true,
    sanctioned: false,
    privateKey,
  });

  assert.equal(att.version, 1);
  assert.equal(att.user, "GBRLZHGNJ4ST7U3FX4C2QG4LBW2V5PBQFTM5A3X5R6AT4LXKQNLJQHCA");
  assert.deepEqual(att.attributes, {
    user: "GBRLZHGNJ4ST7U3FX4C2QG4LBW2V5PBQFTM5A3X5R6AT4LXKQNLJQHCA",
    jurisdiction: "NG",
    accredited: true,
    sanctioned: false,
  });
  assert.match(att.commitment, /^0x[0-9a-f]{64}$/);
  assert.match(att.issuer_pubkey.x, /^0x[0-9a-f]{64}$/);
  assert.match(att.issuer_pubkey.y, /^0x[0-9a-f]{64}$/);
  assert.match(att.signature.R8.x, /^0x[0-9a-f]{64}$/);
  assert.match(att.signature.R8.y, /^0x[0-9a-f]{64}$/);
  assert.match(att.signature.S, /^0x[0-9a-f]{64}$/);
  assert.ok(Number.isFinite(Date.parse(att.created_at)));

  // Recompute the commitment from the public attributes and match.
  const recomputed = computeCommitment(att.attributes, poseidon);
  assert.equal(recomputed, hexToBigInt(att.commitment));

  // Verify the EdDSA signature over the commitment.
  const parsed = parseAttestation(att);
  const ok = eddsa.verifyPoseidon(
    eddsa.F.e(parsed.commitment),
    {
      R8: [eddsa.F.e(parsed.signature.R8[0]), eddsa.F.e(parsed.signature.R8[1])],
      S: parsed.signature.S,
    },
    [eddsa.F.e(parsed.pubkey[0]), eddsa.F.e(parsed.pubkey[1])],
  );
  assert.equal(ok, true, "attestation signature must verify under its issuer pubkey");
});

test("commitment is sensitive to each attribute", async () => {
  const poseidon = await buildPoseidon();
  const base = { user: "alice", jurisdiction: "NG", accredited: true, sanctioned: false };
  const baseCommitment = computeCommitment(base, poseidon);

  assert.notEqual(computeCommitment({ ...base, jurisdiction: "US" }, poseidon), baseCommitment);
  assert.notEqual(computeCommitment({ ...base, accredited: false }, poseidon), baseCommitment);
  assert.notEqual(computeCommitment({ ...base, sanctioned: true }, poseidon), baseCommitment);
  assert.notEqual(computeCommitment({ ...base, user: "bob" }, poseidon), baseCommitment);
});

test("stringToFieldElement is deterministic and field-bounded", async () => {
  const poseidon = await buildPoseidon();
  const order = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const h = stringToFieldElement("NG", poseidon);
  assert.equal(h, stringToFieldElement("NG", poseidon));
  assert.ok(h > 0n && h < order);
});
