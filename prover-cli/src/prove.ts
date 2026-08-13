// prove.ts — CLI + JS SDK for generating ZK eligibility proofs (README
// "Usage" §2). Day 1: placeholder only. Real proof generation lands on Day 2
// (witness generation + snarkjs Groth16 once the circuit is compiled and a
// trusted setup exists).

export function prove(_attestationPath: string, _policy: string): never {
  throw new Error(
    "prove: not implemented yet (Day 2) — requires a compiled " +
      "kyc_eligibility circuit and a Groth16 trusted setup",
  );
}

import { pathToFileURL } from "node:url";

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  try {
    prove(process.argv[2] ?? "", process.argv[3] ?? "");
  } catch (err) {
    console.error(`[prover] ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
