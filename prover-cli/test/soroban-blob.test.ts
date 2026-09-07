import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  encodeProof,
  encodePublicInputs,
  encodeVerificationKey,
  bytesToHex,
  type SnarkJsProof,
  type VerificationKey,
} from "../src/soroban-blob.js";

const BUILD = join(import.meta.dirname, "..", "..", "circuits", "build");

test("encodePublicInputs packs snarkjs signals as 32-byte big-endian", () => {
  const publicJson = JSON.parse(
    readFileSync(join(BUILD, "public.json"), "utf8"),
  ) as string[];

  const blob = encodePublicInputs(publicJson);
  assert.equal(blob.length, publicJson.length * 32);

  // First public signal is the circuit output `eligible` and must be 0…1.
  assert.deepEqual([...blob.subarray(0, 32)], [
    ...Array.from({ length: 31 }, () => 0),
    1,
  ]);
  assert.equal(publicJson[0], "1");
});

test("encodeProof produces the contract's 256-byte proof blob", () => {
  const proof = JSON.parse(
    readFileSync(join(BUILD, "proof.json"), "utf8"),
  ) as SnarkJsProof;

  const blob = encodeProof(proof);
  assert.equal(blob.length, 256);

  // A and C are G1 (64 bytes each); only the top two flag bits must be unset.
  assert.equal(blob[0] & 0xc0, 0, "A (G1) must be uncompressed");
  assert.equal(blob[192] & 0xc0, 0, "C (G1) must be uncompressed");
  assert.equal(blob[64] & 0xc0, 0, "B (G2) must be uncompressed");
});

test("encodeVerificationKey matches the circuit's 6 public signals + IC", () => {
  const vk = JSON.parse(
    readFileSync(join(BUILD, "verification_key.json"), "utf8"),
  ) as VerificationKey;

  const args = encodeVerificationKey(vk);
  assert.equal(args.ic_count, 7); // 1 (constant) + 6 public signals
  assert.equal(args.alpha_g1.length, 2 + 64 * 2);
  assert.equal(args.beta_g2.length, 2 + 128 * 2);
  assert.equal(args.ic_flat.length, 2 + 7 * 64 * 2);

  // A lone G2 point round-trips to exactly 128 bytes (uncompressed format).
  const beta_flat = args.beta_g2.slice(2);
  assert.equal(Buffer.from(beta_flat, "hex").length, 128);
});