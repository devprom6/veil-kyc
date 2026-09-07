// prove.ts — CLI for generating ZK eligibility proofs (README "Usage" §2).
//
//   cd prover-cli
//   npm run prove -- \
//     --attestation ./my_attestation.json \
//     --policy "jurisdiction_not_in:sanctioned_list;accredited:true"
//
// Produces, in the current directory:
//   - input.json          the kyc_eligibility circuit input
//   - proof.json          the Groth16 proof (snarkjs "proof")
//   - public_inputs.json  the public signals (snarkjs "public")
//   - proof.blob.json     the 256-byte proof as the verifier contract expects
//   - public_inputs.blob.json  the public inputs as 32-byte field elements
//
// And, when --out is given, writes those artifacts under `--out`.

import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { buildCircuitInput, type Attestation } from "./build-input.js";
import { encodeProof, encodePublicInputs, type SnarkJsProof } from "./soroban-blob.js";

const execFileAsync = promisify(execFile);

interface ProveArtifacts {
  /** Bytes of the snarkjs witness generation wasm. */
  wasm: string;
  /** Bytes of the snarkjs proving key (final zkey). */
  zkey: string;
  /** Optional caveats propagated to the result. */
  ptau?: string;
}

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

async function resolveSnarkPaths(env: Record<string, string>): Promise<ProveArtifacts> {
  // Resolve relative to the project root (one level above this file's dir).
  const repoRoot = resolve(import.meta.dirname, "..", "..");
  const buildRoot = env["VEIL_KYC_CIRCUITS_BUILD"]
    ? resolve(env["VEIL_KYC_CIRCUITS_BUILD"])
    : resolve(repoRoot, "circuits", "build");
  return {
    wasm: resolve(buildRoot, "kyc_eligibility_js", "kyc_eligibility.wasm"),
    zkey: resolve(buildRoot, "kyc_eligibility_final.zkey"),
  };
}

async function runSnark(
  wasm: string,
  zkey: string,
  inputPath: string,
  proofPath: string,
  publicPath: string,
): Promise<void> {
  await execFileAsync(
    "snarkjs",
    ["groth16", "fullprove", inputPath, wasm, zkey, proofPath, publicPath],
    { maxBuffer: 1024 * 1024 * 64 },
  );
}

export async function prove(
  attestationPath: string,
  policy: string,
  opts: { out?: string; context?: string } = {},
): Promise<{ proof: string; publicInputs: string }> {
  const attestation = JSON.parse(
    await readFile(resolve(attestationPath), "utf8"),
  ) as Attestation;

  const input = await buildCircuitInput(attestation, policy, opts.context);

  // Resolve the circuit artifacts (trusted setup) for witness generation.
  const { wasm, zkey } = await resolveSnarkPaths({});

  const outDir = opts.out ? resolve(opts.out) : process.cwd();
  await mkdir(outDir, { recursive: true });

  const inputPath = resolve(outDir, "input.json");
  const proofPath = resolve(outDir, "proof.json");
  const publicPath = resolve(outDir, "public_inputs.json");
  const proofBlobPath = resolve(outDir, "proof.blob.json");
  const publicBlobPath = resolve(outDir, "public_inputs.blob.json");

  await writeFile(inputPath, JSON.stringify(input, null, 2) + "\n", "utf8");

  await runSnark(wasm, zkey, inputPath, proofPath, publicPath);

  const proof = JSON.parse(await readFile(proofPath, "utf8")) as SnarkJsProof;
  const publicInputs = JSON.parse(await readFile(publicPath, "utf8")) as string[];

  // Bridge to the Soroban verifier contract's expected byte format.
  const proofBlob = encodeProof(proof);
  const publicBlob = encodePublicInputs(publicInputs);
  await writeFile(
    proofBlobPath,
    JSON.stringify({ proof_bytes: Buffer.from(proofBlob).toString("hex") }, null, 2) + "\n",
    "utf8",
  );
  await writeFile(
    publicBlobPath,
    JSON.stringify({ public_inputs_bytes: Buffer.from(publicBlob).toString("hex") }, null, 2) +
      "\n",
    "utf8",
  );

  return { proof: proofPath, publicInputs: publicPath };
}

const isMain =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  (async () => {
    const args = parseArgs(process.argv.slice(2));
    const attestationPath = args["attestation"];
    const policy = args["policy"];
    if (!attestationPath) {
      console.error("prove: --attestation <path> is required");
      process.exit(1);
    }
    if (!policy) {
      console.error("prove: --policy \"<jurisdiction_not_in:sanctioned_list;...>\" is required");
      process.exit(1);
    }

    try {
      const { proof, publicInputs } = await prove(attestationPath, policy, {
        out: args["out"],
        context: args["context"],
      });
      console.log("[prover] proof.json            ->", proof);
      console.log("[prover] public_inputs.json    ->", publicInputs);
      console.log("[prover] proof.blob.json       ->", dirname(proof) + "/proof.blob.json");
      console.log("[prover] public_inputs.blob.json ->", dirname(publicInputs) + "/public_inputs.blob.json");
    } catch (err) {
      console.error(
        `[prover] ${err instanceof Error ? err.message : String(err)}`,
      );
      process.exit(1);
    }
  })();
}
