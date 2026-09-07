// soroban-blob.ts
//
// Byte-level bridge between snarkjs Groth16 output and the Soroban verifier
// contract's expected argument types (README "Smart Contract Interface", and
// docs/decisions.md Day 4).
//
// The Soroban verifier contract consumes:
//   - proof:         BytesN<256>   — serialized Groth16 proof (A || B || C)
//   - public_inputs: Bytes          — N × 32-byte BN254 field elements
//   - set_verification_key: 4 curve points + flat IC bytes
//
// On-chain serialization is the Ethereum alt_bn128 precompile layout used by
// Soroban's Protocol 25 host functions (see soroban-sdk crypto/bn254.rs):
//   - Bn254Fp:  32-byte big-endian field element
//   - G1 point: be(X) || be(Y), 64 bytes, flags unset
//   - G2 point: be(c1_X) || be(c0_X) || be(c1_Y) || be(c0_Y),
//               128 bytes (each coordinate is an Fp2 pair, imaginary c1 first)
//
// snarkjs emits the same field elements as decimal strings (G2 coordinate
// pairs are {real, imaginary}), so the conversion is purely byte packing —
// no endian swaps, no base changes.

export const BN254_FIELD_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ---------------------------------------------------------------------------
// Field / big-int helpers
// ---------------------------------------------------------------------------

export function toHex(v: bigint): string {
  return "0x" + v.toString(16).padStart(64, "0");
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, "");
  const bytes = new Uint8Array(Math.ceil(clean.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Buffer.from(bytes).toString("hex");
}

/** Reduce `v` modulo the BN254 base field order `p` and fit into 32 bytes BE. */
export function fp32(v: bigint): Uint8Array {
  const r = ((v % BN254_FIELD_ORDER) + BN254_FIELD_ORDER) % BN254_FIELD_ORDER;
  const out = Buffer.alloc(32);
  const hex = r.toString(16);
  out.set(Buffer.from(hex.padStart(64, "0"), "hex"));
  return out;
}

// ---------------------------------------------------------------------------
// Curve point serialization (alt_bn128 / Soroban layout)
// ---------------------------------------------------------------------------

export type G1 = [bigint, bigint];
export type G2 = [[bigint, bigint], [bigint, bigint]];

/** A snarkjs point tuple: [x, y] or projective [x, y, z=1]. */
export type SnarkPointTuple = (string | number)[];

/** Serialize an affine G1 point to 64 bytes: be(X) || be(Y). */
export function encodeG1(x: bigint, y: bigint): Uint8Array {
  const out = Buffer.alloc(64);
  out.set(fp32(x), 0);
  out.set(fp32(y), 32);
  return out;
}

/**
 * Serialize an affine G2 point to 128 bytes in Soroban's Fp2 layout:
 * be(c1_X) || be(c0_X) || be(c1_Y) || be(c0_Y).
 *
 * A G2 point from snarkjs is the projective tuple [X, Y, Z] where each Fp2
 * coordinate is [real(c0), imaginary(c1)] — e.g. `proof.pi_b` (3 elements)
 * or a `vk_*_2` entry (3 elements). The two coordinates are passed in.
 */
export function encodeG2(coordX: SnarkPointTuple, coordY: SnarkPointTuple): Uint8Array {
  const xReal = BigInt(coordX[0]);
  const xImag = BigInt(coordX[1]);
  const yReal = BigInt(coordY[0]);
  const yImag = BigInt(coordY[1]);
  const out = Buffer.alloc(128);
  out.set(fp32(xImag), 0);
  out.set(fp32(xReal), 32);
  out.set(fp32(yImag), 64);
  out.set(fp32(yReal), 96);
  return out;
}

// ---------------------------------------------------------------------------
// snarkjs-proof → Soroban contract blobs
// ---------------------------------------------------------------------------

export interface SnarkJsProof {
  pi_a: (string | string[])[];
  pi_b: (string | string[])[][];
  pi_c: (string | string[])[];
  [k: string]: unknown;
}

/** Parse a snarkjs proof value into a bigint (scalar) or pair (G2 coord). */
function toBigInt(v: string | string[]): bigint | [bigint, bigint] {
  if (Array.isArray(v)) return [BigInt(v[1] ?? 0), BigInt(v[0] ?? 0)];
  return BigInt(v);
}

/**
 * Serialize a snarkjs `proof.json` to the verifier contract's 256-byte blob:
 * A (G1) || B (G2) || C (G1).
 */
export function encodeProof(p: SnarkJsProof): Uint8Array {
  const a = encodeG1(BigInt(p.pi_a[0] as string), BigInt(p.pi_a[1] as string));
  const b = encodeG2(p.pi_b[0] as SnarkPointTuple, p.pi_b[1] as SnarkPointTuple);
  const c = encodeG1(BigInt(p.pi_c[0] as string), BigInt(p.pi_c[1] as string));
  return Buffer.concat([a, b, c]);
}

/**
 * Serialize snarkjs public signals (`public.json`, decimal strings, in the
 * exact order snarkjs emits them) to the verifier contract's flat `Bytes`
 * blob of N × 32-byte big-endian field elements.
 */
export function encodePublicInputs(publicSignals: string[]): Uint8Array {
  return Buffer.concat(publicSignals.map((s) => fp32(BigInt(s))));
}

// ---------------------------------------------------------------------------
// Verification-key → verifier contract storage args
// ---------------------------------------------------------------------------

export interface VerificationKey {
  protocol: string;
  curve: string;
  nPublic: number;
  vk_alpha_1: SnarkPointTuple;
  vk_beta_2: [SnarkPointTuple, SnarkPointTuple, SnarkPointTuple];
  vk_gamma_2: [SnarkPointTuple, SnarkPointTuple, SnarkPointTuple];
  vk_delta_2: [SnarkPointTuple, SnarkPointTuple, SnarkPointTuple];
  IC: SnarkPointTuple[];
}

export interface VkContractArgs {
  alpha_g1: string;
  beta_g2: string;
  gamma_g2: string;
  delta_g2: string;
  ic_flat: string;
  ic_count: number;
}

/**
 * Convert the snarkjs `verification_key.json` into the verifier contract's
 * `set_verification_key` argument blob. IC points are X || Y (64 bytes each),
 * packed contiguously; the contract slices them out on deploy.
 */
export function encodeVerificationKey(vk: VerificationKey): VkContractArgs {
  const alpha = encodeG1(BigInt(vk.vk_alpha_1[0] as string), BigInt(vk.vk_alpha_1[1] as string));
  const beta = encodeG2(vk.vk_beta_2[0], vk.vk_beta_2[1]);
  const gamma = encodeG2(vk.vk_gamma_2[0], vk.vk_gamma_2[1]);
  const delta = encodeG2(vk.vk_delta_2[0], vk.vk_delta_2[1]);

  const icFlat = Buffer.concat(
    vk.IC.map((ic) => encodeG1(BigInt(ic[0] as string), BigInt(ic[1] as string))),
  );

  return {
    alpha_g1: bytesToHex(alpha),
    beta_g2: bytesToHex(beta),
    gamma_g2: bytesToHex(gamma),
    delta_g2: bytesToHex(delta),
    ic_flat: bytesToHex(icFlat),
    ic_count: vk.IC.length,
  };
}