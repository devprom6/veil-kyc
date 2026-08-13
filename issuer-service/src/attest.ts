// attest.ts — reference off-chain issuer (README "Usage" §1).
//
// Day 1 scope: CLI-only. Takes user attributes, computes a Poseidon
// commitment over them, produces a BabyJubJub EdDSA signature over the
// commitment (compatible with the kyc_eligibility circuit on Day 2), and
// writes the attestation JSON to disk. No HTTP, no database, no auth.
//
//   npm run attest -- --user <pubkey> --jurisdiction NG \
//     --accredited true --sanctioned false

import "dotenv/config";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildEddsa, buildPoseidon, type EdDSA, type PoseidonHash } from "circomlibjs";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
  /** Poseidon(attributes) serialized as a 64-hex-char BN254 field element. */
  commitment: string;
  issuer_pubkey: { x: string; y: string };
  /** EdDSA(Poseidon) signature over the commitment: R8 = (x, y), S. */
  signature: { R8: { x: string; y: string }; S: string };
  created_at: string;
}

// ---------------------------------------------------------------------------
// Field element helpers
// ---------------------------------------------------------------------------

function poseidonToBigInt(inputs: (bigint | number)[], poseidon: PoseidonHash): bigint {
  const out = poseidon(inputs);
  return poseidon.F.toObject(poseidon.F.e(out));
}

function toHex(v: bigint): string {
  return "0x" + v.toString(16).padStart(64, "0");
}

export function hexToBigInt(hex: string): bigint {
  return BigInt(hex.startsWith("0x") ? hex : `0x${hex}`);
}

// Encode a string as a field element: Poseidon over its UTF-8 bytes, chunked
// to 31 bytes per element so every chunk stays below the BN254 field order.
export function stringToFieldElement(s: string, poseidon: PoseidonHash): bigint {
  const bytes = Buffer.from(s, "utf8");
  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    chunks.push(BigInt(`0x${bytes.subarray(i, i + 31).toString("hex")}`));
  }
  if (chunks.length === 0) chunks.push(0n);
  return poseidonToBigInt(chunks, poseidon);
}

export function computeCommitment(attributes: AttestationAttributes, poseidon: PoseidonHash): bigint {
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

// ---------------------------------------------------------------------------
// Issuer key management (dev-only; no secrets hardcoded)
// ---------------------------------------------------------------------------

const DEV_KEY_FILE = fileURLToPath(new URL("../.dev/issuer_key.json", import.meta.url));

function loadOrCreateIssuerKey(): Uint8Array {
  const envKey = process.env.ISSUER_PRIVATE_KEY;
  if (envKey) {
    const hex = envKey.replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new Error("ISSUER_PRIVATE_KEY must be a 32-byte private key as 64 hex chars");
    }
    return Buffer.from(hex, "hex");
  }
  if (existsSync(DEV_KEY_FILE)) {
    const parsed = JSON.parse(readFileSync(DEV_KEY_FILE, "utf8")) as { privateKey: string };
    return Buffer.from(parsed.privateKey, "hex");
  }
  const key = randomBytes(32);
  mkdirSync(join(DEV_KEY_FILE, ".."), { recursive: true });
  writeFileSync(
    DEV_KEY_FILE,
    JSON.stringify(
      { privateKey: key.toString("hex"), note: "dev-only issuer key — do not use in production" },
      null,
      2,
    ) + "\n",
  );
  console.log(`[issuer] generated new dev issuer key -> ${DEV_KEY_FILE}`);
  return key;
}

// ---------------------------------------------------------------------------
// Attestation creation
// ---------------------------------------------------------------------------

export interface CreateAttestationParams extends AttestationAttributes {
  /** BabyJubJub private key (32 bytes). Defaults to the persisted dev key. */
  privateKey?: Uint8Array;
}

export async function createAttestation(params: CreateAttestationParams): Promise<Attestation> {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();

  const attributes: AttestationAttributes = {
    user: params.user,
    jurisdiction: params.jurisdiction,
    accredited: params.accredited,
    sanctioned: params.sanctioned,
  };

  const commitment = computeCommitment(attributes, poseidon);
  const privateKey = params.privateKey ?? loadOrCreateIssuerKey();
  const pubkey = eddsa.prv2pub(privateKey);
  const signature = eddsa.signPoseidon(privateKey, eddsa.F.e(commitment));

  return {
    version: 1,
    user: attributes.user,
    attributes,
    commitment: toHex(commitment),
    issuer_pubkey: { x: toHex(eddsa.F.toObject(pubkey[0])), y: toHex(eddsa.F.toObject(pubkey[1])) },
    signature: {
      R8: {
        x: toHex(eddsa.F.toObject(signature.R8[0])),
        y: toHex(eddsa.F.toObject(signature.R8[1])),
      },
      S: toHex(signature.S),
    },
    created_at: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      out[key] = next;
      i++;
    } else {
      out[key] = "true";
    }
  }
  return out;
}

function parseBool(v: string | undefined, fallback: boolean): boolean {
  if (v === undefined) return fallback;
  switch (v.toLowerCase()) {
    case "true":
    case "1":
    case "yes":
      return true;
    case "false":
    case "0":
    case "no":
      return false;
    default:
      throw new Error(`invalid boolean value: "${v}" (expected true/false)`);
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const user = args["user"];
  const jurisdiction = args["jurisdiction"];
  if (!user) throw new Error("--user <pubkey> is required");
  if (!jurisdiction) throw new Error("--jurisdiction <code> is required");

  const accredited = parseBool(args["accredited"], false);
  const sanctioned = parseBool(args["sanctioned"], false);

  const attestation = await createAttestation({ user, jurisdiction, accredited, sanctioned });

  const outDir = process.env.ATTESTATION_OUT_DIR ?? "attestations";
  await mkdir(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const file = join(outDir, `${stamp}-${user}.json`);
  await writeFile(file, JSON.stringify(attestation, null, 2) + "\n", "utf8");

  console.log(`[issuer] attestation written to ${file}`);
  console.log(`[issuer] commitment   ${attestation.commitment}`);
  console.log(
    `[issuer] issuer_pubkey x=${attestation.issuer_pubkey.x} y=${attestation.issuer_pubkey.y}`,
  );
  console.log(
    `[issuer] signature     R8=(${attestation.signature.R8.x}, ${attestation.signature.R8.y}) S=${attestation.signature.S}`,
  );
}

const isMain =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  main().catch((err: unknown) => {
    console.error(`[issuer] error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
