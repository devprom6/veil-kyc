// deploy-params.ts
//
// Emits the on-chain configuration JSON consumed by scripts/deploy_testnet.sh:
// the gate's PolicyParams (with the same sanctioned-list root the prover uses)
// and the stablecoin initialize metadata.
//
//   npx tsx scripts/deploy-params.ts <verifier_id> <token_id> <gate_id>

import { buildPoseidon } from "circomlibjs";
import { sanctionedListRoot } from "../prover-cli/src/build-input.js";

async function main(): Promise<void> {
  const [verifierId, tokenId, gateId] = process.argv.slice(2);
  if (!verifierId || !tokenId || !gateId) {
    throw new Error("usage: deploy-params.ts <verifier_id> <token_id> <gate_id>");
  }

  const poseidon = await buildPoseidon();
  const sanctioned = sanctionedListRoot(poseidon).toString(16).padStart(64, "0");

  const out = {
    policy: {
      policy_id: "USDC_NG",
      sanctioned_list_root: sanctioned,
      require_accredited: true,
      verifier: verifierId,
      token: tokenId,
    },
    token: {
      name: "Veil Demo USD",
      symbol: "VDUSD",
      decimals: 7,
      gate: gateId,
    },
  };

  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
