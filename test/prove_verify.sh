#!/usr/bin/env bash
# test/prove_verify.sh
#
# End-to-end local test: generate inputs → prove → verify (off-chain).
# Requires: the trusted setup artifacts in circuits/build/ (run
# scripts/setup_trusted.sh first) and snarkjs + node.
#
# Usage:
#   ./test/prove_verify.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/circuits/build"
WASM="$BUILD_DIR/kyc_eligibility_js/kyc_eligibility.wasm"
ZKEY="$BUILD_DIR/kyc_eligibility_final.zkey"
VK="$BUILD_DIR/verification_key.json"

PASS=0
FAIL=0

pass() { printf '  \033[32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }

echo "=== veil-kyc: local proof generation + verification test ==="
echo ""

# --- Prerequisites check ---
for f in "$WASM" "$ZKEY" "$VK"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: missing $f — run scripts/setup_trusted.sh first."
    exit 1
  fi
done

# --- Step 1: Generate test inputs ---
echo "[1/3] Generating test inputs..."
"$ROOT_DIR/node_modules/.bin/tsx" "$SCRIPT_DIR/generate_inputs.ts"
echo ""

INPUTS_DIR="$SCRIPT_DIR/circuit_inputs"

# --- Step 2: Test valid case ---
echo "[2/3] Testing valid proof (NG, accredited=true)..."
snarkjs groth16 fullprove \
  "$INPUTS_DIR/valid.json" "$WASM" "$ZKEY" \
  "$BUILD_DIR/proof.json" "$BUILD_DIR/public.json" 2>/dev/null

if snarkjs groth16 verify "$VK" "$BUILD_DIR/public.json" "$BUILD_DIR/proof.json" 2>&1 | grep -q "OK"; then
  pass "valid proof generated and verified off-chain"
else
  fail "valid proof verification failed"
fi

# Verify public output: eligible == 1
ELIGIBLE=$(node -e "const p=require('$BUILD_DIR/public.json'); console.log(p[0])")
if [ "$ELIGIBLE" = "1" ]; then
  pass "public output eligible == 1"
else
  fail "public output eligible == $ELIGIBLE (expected 1)"
fi

echo ""

# --- Step 3: Test invalid cases ---
echo "[3/3] Testing invalid proofs (should all fail to generate witness)..."

# 3a: Invalid signature
if snarkjs groth16 fullprove \
  "$INPUTS_DIR/invalid_signature.json" "$WASM" "$ZKEY" \
  "$BUILD_DIR/proof_bad.json" "$BUILD_DIR/public_bad.json" 2>/dev/null; then
  fail "invalid signature should not produce a valid witness"
else
  pass "invalid signature correctly rejected (witness generation fails)"
fi

# 3b: Sanctioned jurisdiction (KP)
if snarkjs groth16 fullprove \
  "$INPUTS_DIR/invalid_sanctioned.json" "$WASM" "$ZKEY" \
  "$BUILD_DIR/proof_bad.json" "$BUILD_DIR/public_bad.json" 2>/dev/null; then
  fail "sanctioned jurisdiction should not produce a valid witness"
else
  pass "sanctioned jurisdiction correctly rejected (jurisdiction constraint fails)"
fi

# 3c: Invalid accredited (changes commitment → invalidates signature)
if snarkjs groth16 fullprove \
  "$INPUTS_DIR/invalid_accredited.json" "$WASM" "$ZKEY" \
  "$BUILD_DIR/proof_bad.json" "$BUILD_DIR/public_bad.json" 2>/dev/null; then
  fail "accredited=false should not produce a valid witness"
else
  pass "accredited=false correctly rejected (commitment/signature mismatch)"
fi

echo ""

# --- Summary ---
TOTAL=$((PASS + FAIL))
echo "=== Results: $PASS/$TOTAL passed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Some tests FAILED."
  exit 1
else
  echo "All tests passed."
  exit 0
fi
