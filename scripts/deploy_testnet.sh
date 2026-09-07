#!/usr/bin/env bash
# veil-kyc: deploy verifier, policy_gate, and stablecoin_demo to Stellar
# testnet in dependency order, initialize them, and record contract IDs in
# scripts/testnet_addresses.json.
#
# Idempotent: existing contract IDs are reused, and instance state
# (verification key / policy / token init / funding) is only set once each.
#
# Usage:
#   ./scripts/deploy_testnet.sh [--fresh]
#
#   --fresh   re-deploy all three contracts (new IDs) regardless of the recorded
#             ones. Instances are re-initialized from scratch.
#
# Prereq: `stellar` CLI configured for testnet with an auth'able source account
#         (default: `deployer` — override with SOURCE_ACCOUNT).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ADDRS="$SCRIPT_DIR/testnet_addresses.json"
WASM_DIR="$ROOT_DIR/contracts/target/wasm32v1-none/release"

NETWORK="${NETWORK:-testnet}"
SOURCE="${SOURCE_ACCOUNT:-deployer}"
MINT_AMOUNT="${MINT_AMOUNT:-1000000}"
FRESH=0
for a in "$@"; do [ "$a" = "--fresh" ] && FRESH=1; done

POLICY_ID="USDC_NG"
SANCTIONED_ROOT="0216cbd515af6cfaada0c1ebfc7da7c202f1355efe516fa81e832d4e7d46fa8a"
TOKEN_NAME="Veil Demo USD"
TOKEN_SYMBOL="VDUSD"
TOKEN_DECIMALS=7

# ---- small JSON helpers ------------------------------------------------
# get_contract NAME  -> contract id or empty
get_contract() {
  node -p "const a=require('$ADDRS'); a.contracts ? (a.contracts['$1'] ?? '') : ''" 2>/dev/null || true
}
# get_flag NAME -> "true"/"" for a top-level boolean marker
get_flag() {
  node -p "const a=require('$ADDRS'); a['$1'] === true ? 'true' : ''" 2>/dev/null || true
}
set_flag() { # set_flag NAME
  node -e "const fs=require('fs'); const a=require('$ADDRS'); a['$1']=true; fs.writeFileSync('$ADDRS', JSON.stringify(a, null, 2)+'\n')"
}
record_ids() { # record_ids VERIFIER GATE TOKEN
  node -e "
    const fs=require('fs');
    const a=require('$ADDRS');
    a.network='$NETWORK';
    a.deployed_at=new Date().toISOString();
    a.contracts=a.contracts || {};
    a.contracts.verifier='$1';
    a.contracts.policy_gate='$2';
    a.contracts.stablecoin_demo='$3';
    fs.writeFileSync('$ADDRS', JSON.stringify(a, null, 2)+'\n');
  "
}
deploy_contract() { # deploy_contract ALIAS WASM
  local alias="$1" wasm="$2"
  stellar contract deploy \
    --wasm "$wasm" \
    --alias "$alias" \
    --source-account "$SOURCE" \
    --network "$NETWORK" \
    2>/dev/null | tail -1
}

# ------------------------------------------------------------------------
mkdir -p "$(dirname "$ADDRS")"
[ -f "$ADDRS" ] || printf '{"network":"testnet","contracts":{}}\n' > "$ADDRS"

if [ "$FRESH" = "1" ]; then
  echo "== fresh deploy requested; ignoring recorded IDs =="
  VERIFIER_ID=""; GATE_ID=""; TOKEN_ID=""
else
  VERIFIER_ID="$(get_contract verifier)"
  GATE_ID="$(get_contract policy_gate)"
  TOKEN_ID="$(get_contract stablecoin_demo)"
fi

# 1-3) Deploy (or reuse) -------------------------------------------------
if [ -n "$VERIFIER_ID" ] && [ -n "$GATE_ID" ] && [ -n "$TOKEN_ID" ]; then
  echo ">> Reusing recorded contract IDs (verifier=$VERIFIER_ID ...). Use --fresh to redeploy."
else
  echo "[1/5] Deploying verifier set..."
  [ -n "$VERIFIER_ID" ] || VERIFIER_ID="$(deploy_contract veil-verifier "$WASM_DIR/verifier.wasm")"
  echo "[2/5] Deploying policy_gate..."
  [ -n "$GATE_ID" ] || GATE_ID="$(deploy_contract veil-policygate "$WASM_DIR/policy_gate.wasm")"
  echo "[3/5] Deploying stablecoin_demo..."
  [ -n "$TOKEN_ID" ] || TOKEN_ID="$(deploy_contract veil-stablecoin "$WASM_DIR/stablecoin_demo.wasm")"
  record_ids "$VERIFIER_ID" "$GATE_ID" "$TOKEN_ID"
  echo "   verifier     = $VERIFIER_ID"
  echo "   policy_gate  = $GATE_ID"
  echo "   stablecoin   = $TOKEN_ID"
fi

# 4) Verifier: set Groth16 verification key (idempotent) -----------------
echo "[4/5] Configuring verifier verification key..."
if [ "$(get_flag verifier_vk_set)" != "true" ] || [ "$FRESH" = "1" ]; then
  TMPVK="$(mktemp)"
  npx tsx "$SCRIPT_DIR/vk2blob.ts" > "$TMPVK"
  ALPHA="$(node -p "require('$TMPVK').alpha_g1")"
  BETA="$(node -p "require('$TMPVK').beta_g2")"
  GAMMA="$(node -p "require('$TMPVK').gamma_g2")"
  DELTA="$(node -p "require('$TMPVK').delta_g2")"
  IC="$(node -p "require('$TMPVK').ic_flat")"
  ICC="$(node -p "require('$TMPVK').ic_count")"
  rm -f "$TMPVK"
  stellar contract invoke --id "$VERIFIER_ID" --network "$NETWORK" --source-account "$SOURCE" \
    -- set_verification_key \
    --vk_alpha_g1 "$ALPHA" --vk_beta_g2 "$BETA" --vk_gamma_g2 "$GAMMA" \
    --vk_delta_g2 "$DELTA" --vk_ic "$IC" --vk_ic_count "$ICC"
  set_flag verifier_vk_set
else
  echo "   verification key already set."
fi

# 5) Stablecoin init + gate policy + funding -----------------------------
echo "[5/5] Initializing stablecoin, setting policy, funding the gate..."
if [ "$(get_flag stablecoin_initialized)" != "true" ] || [ "$FRESH" = "1" ]; then
  stellar contract invoke --id "$TOKEN_ID" --network "$NETWORK" --source-account "$SOURCE" \
    -- initialize \
    --admin "$SOURCE" --name "\"$TOKEN_NAME\"" --symbol "\"$TOKEN_SYMBOL\"" \
    --decimals "$TOKEN_DECIMALS" --gate "$GATE_ID"
  set_flag stablecoin_initialized
fi

stellar contract invoke --id "$GATE_ID" --network "$NETWORK" --source-account "$SOURCE" \
  -- set_policy \
  --admin "$SOURCE" --policy_id "$POLICY_ID" \
  --params "{\"require_accredited\":true,\"sanctioned_list_root\":\"$SANCTIONED_ROOT\",\"token\":\"$TOKEN_ID\",\"verifier\":\"$VERIFIER_ID\"}"

stellar contract invoke --id "$TOKEN_ID" --network "$NETWORK" --source-account "$SOURCE" \
  -- mint --to "$GATE_ID" --amount "$MINT_AMOUNT"

echo ""
echo "== Deploy complete =="
echo "verifier     $VERIFIER_ID"
echo "policy_gate  $GATE_ID"
echo "stablecoin   $TOKEN_ID"
echo "Contract IDs recorded -> $ADDRS"
