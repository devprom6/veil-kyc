// vk2blob.ts
//
// Emits the verifier contract's `set_verification_key` arguments as JSON,
// derived from the snarkjs `verification_key.json`. The deploy script
// consumes this to initialize the on-chain verifier with the Groth16 key.
//
//   npx tsx scripts/vk2blob.ts <path-to-verification_key.json>
//
// Output (JSON):
//   { alpha_g1, beta_g2, gamma_g2, delta_g2, ic_flat, ic_count }

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  encodeVerificationKey,
  type VerificationKey,
} from "../prover-cli/src/soroban-blob.js";

const DEFAULT_VK = resolve(import.meta.dirname, "..", "circuits", "build", "verification_key.json");

const vkPath = process.argv[2] ? resolve(process.argv[2]) : DEFAULT_VK;
const vk = JSON.parse(readFileSync(vkPath, "utf8")) as VerificationKey;

if (vk.protocol !== "groth16" || vk.curve !== "bn128") {
  throw new Error(`expected a bn128 groth16 verification key (got ${vk.protocol}/${vk.curve})`);
}

// The stellar CLI expects raw hex bytes (no 0x prefix), so strip it here.
const args = encodeVerificationKey(vk);
const unprefixed = {
  alpha_g1: args.alpha_g1.slice(2),
  beta_g2: args.beta_g2.slice(2),
  gamma_g2: args.gamma_g2.slice(2),
  delta_g2: args.delta_g2.slice(2),
  ic_flat: args.ic_flat.slice(2),
  ic_count: args.ic_count,
};
process.stdout.write(JSON.stringify(unprefixed, null, 2) + "\n");
