#!/usr/bin/env bash
# veil-kyc: run a full end-to-end policy-gated transfer on Stellar testnet,
# driven entirely through the README "Usage" commands.
#
# Flow:
#   1. issuer-service `npm run attest`  -> attestation JSON
#   2. prover-cli `npm run prove`       -> proof.json + public_inputs.json (and
#                                         the verifier-format blob files)
#   3. stellar contract invoke verify_and_transfer -> real on-chain gated transfer
#   4. stellar contract invoke is_nullifier_used   -> confirms the nullifier is spent
#
# Usage:
#   ./scripts/run_e2e.sh [--user alice] [--jurisdiction NG] [--amount 1000]
#
# Reads contract IDs from scripts/testnet_addresses.json. Source account and
# recipient identity default to `deployer` and `recipient`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ADDRS="$SCRIPT_DIR/testnet_addresses.json"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

NETWORK="${NETWORK:-testnet}"
SOURCE="${SOURCE_ACCOUNT:-deployer}"
RECIPIENT_ID="${RECIPIENT_ID:-recipient}"
USER="${USER_:-alice}"
JURISDICTION="${JURISDICTION:-NG}"
AMOUNT="${AMOUNT:-1000}"

GATE_ID="$(node -p "require('$ADDRS').contracts.policy_gate")"

echo "=== veil-kyc testnet end-to-end run ==="
echo "policy_gate = $GATE_ID"
echo "user        = $USER (jurisdiction $JURISDICTION)"
echo "recipient   = $RECIPIENT_ID"
echo ""

# --- 1. Issue an attestation (README Usage §1) --------------------------
echo "[1/3] Issuing attestation..."
cd "$ROOT_DIR/issuer-service"
ATT_OUT="$(npm run attest -- --user "$USER" --jurisdiction "$JURISDICTION" --accredited true --sanctioned false 2>/dev/null | grep -oE 'attestations/[^ ]+\.json' | head -1)"
ATTESTATION="$ROOT_DIR/issuer-service/$ATT_OUT"
echo "   attestation -> $ATTESTATION"
echo ""

# --- 2. Generate a proof (README Usage §2) ------------------------------
echo "[2/3] Generating proof..."
cd "$ROOT_DIR/prover-cli"
npm run prove -- \
  --attestation "$ATTESTATION" \
  --policy "jurisdiction_not_in:sanctioned_list;accredited:true" \
  --out "$WORK" >/dev/null
PROOF_JSON="$WORK/proof.json"
PUBLIC_JSON="$WORK/public_inputs.json"
PROOF_BLOB="$WORK/proof_blob_hex.txt"
PUBLIC_BLOB="$WORK/public_inputs_blob_hex.txt"
node -p "require('$WORK/proof.blob.json').proof_bytes" > "$PROOF_BLOB"
node -p "require('$WORK/public_inputs.blob.json').public_inputs_bytes" > "$PUBLIC_BLOB"
PROOF_HEX="$(cat "$PROOF_BLOB")"
PUBLIC_HEX="$(cat "$PUBLIC_BLOB")"
echo "   proof ($((${#PROOF_HEX}/2)) bytes) -> $PROOF_JSON"
echo "   public_inputs ($((${#PUBLIC_HEX}/2)) bytes) -> $PUBLIC_JSON"
echo ""

# --- 3. Submit and verify on-chain (README Usage §3) --------------------
echo "[3/3] Submitting verify_and_transfer on testnet..."
cd "$ROOT_DIR"
stellar contract invoke \
  --id "$GATE_ID" \
  --network "$NETWORK" \
  --source-account "$SOURCE" \
  -- verify_and_transfer \
  --proof "$PROOF_HEX" \
  --public_inputs "$PUBLIC_HEX" \
  --recipient "$RECIPIENT_ID" \
  --amount "$AMOUNT"
echo ""

# --- Post-condition: nullifier must now be spent ------------------------
echo "== Post-conditions =="
NULLIFIER_HEX="$(node -p "require('$WORK/public_inputs.json')[3] ? (BigInt(require('$WORK/public_inputs.json')[3]).toString(16).padStart(64,'0')) : 'nullifier-from-public-inputs-blob'")"
# The nullifier is public signal index 3; the gate records it at byte offset 3*32.
NULL_FROM_BLOB="$(node -e "const b=Buffer.from('$PUBLIC_HEX','hex'); process.stdout.write(b.subarray(3*32,4*32).toString('hex'))")"
echo "   nullifier (bytes 96..128 of public inputs) = $NULL_FROM_BLOB"
USED="$(stellar contract invoke --id "$GATE_ID" --network "$NETWORK" --source-account "$SOURCE" -- is_nullifier_used --nullifier "$NULL_FROM_BLOB" 2>/dev/null | tail -1)"
echo "   is_nullifier_used -> $USED"
if [ "$USED" = "true" ]; then
  echo ""
  echo "== SUCCESS: policy-gated transfer verified and spend confirmed =="
else
  echo ""
  echo "== WARNING: is_nullifier_used did not return true =="
fi
