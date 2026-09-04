#!/usr/bin/env bash
# scripts/setup_trusted.sh
#
# Local (test-only) Groth16 trusted setup for kyc_eligibility.circom.
#
# This produces a sample .ptau and proving/verification keys suitable for
# local development and testing. It is NOT production-safe — the README's
# Limitations section explicitly notes that a proper multi-party ceremony
# is required before any real deployment.
#
# Prerequisites: circom, snarkjs
#
# Usage:
#   ./scripts/setup_trusted.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CIRCUITS_DIR="$ROOT_DIR/circuits"
BUILD_DIR="$CIRCUITS_DIR/build"
CIRCOMLIB_DIR="$CIRCUITS_DIR/vendor/circomlib"

PTAU_POWER=12  # 2^12 = 4096 constraints max; our circuit has ~9900 non-linear
               # constraints, so we need power >= 14. Using 14.
PTAU_POWER=14  # 2^14 = 16384 constraints — sufficient for kyc_eligibility

mkdir -p "$BUILD_DIR"

echo "=== veil-kyc: local Groth16 trusted setup (TEST ONLY) ==="
echo ""

# --- Step 1: Compile the circuit ---
echo "[1/6] Compiling kyc_eligibility.circom..."
circom "$CIRCUITS_DIR/kyc_eligibility.circom" \
  --r1cs --wasm --sym \
  -o "$BUILD_DIR" \
  -l "$CIRCOMLIB_DIR" \
  -l "$CIRCUITS_DIR"
echo "  -> $BUILD_DIR/kyc_eligibility.r1cs"
echo "  -> $BUILD_DIR/kyc_eligibility_js/kyc_eligibility.wasm"
echo ""

# --- Step 2: Print R1CS info ---
echo "[2/6] R1CS info:"
snarkjs r1cs info "$BUILD_DIR/kyc_eligibility.r1cs"
echo ""

# --- Step 3: Powers of Tau ceremony (Phase 1) ---
echo "[3/6] Creating powers of tau (phase 1, power=$PTAU_POWER)..."
snarkjs powersoftau new bn128 "$PTAU_POWER" \
  "$BUILD_DIR/pot_${PTAU_POWER}.ptau" -v
echo ""

echo "[4/6] Contributing to powers of tau..."
snarkjs powersoftau contribute \
  "$BUILD_DIR/pot_${PTAU_POWER}.ptau" \
  "$BUILD_DIR/pot_${PTAU_POWER}_contributed.ptau" \
  --name="veil-kyc test contribution" \
  -e="random entropy for test only" -v
echo ""

echo "  Preparing phase 2..."
snarkjs powersoftau prepare phase2 \
  "$BUILD_DIR/pot_${PTAU_POWER}_contributed.ptau" \
  "$BUILD_DIR/pot_final.ptau" -v
echo ""

# --- Step 4: Groth16 setup (Phase 2) ---
echo "[5/6] Groth16 setup..."
snarkjs groth16 setup \
  "$BUILD_DIR/kyc_eligibility.r1cs" \
  "$BUILD_DIR/pot_final.ptau" \
  "$BUILD_DIR/kyc_eligibility_0000.zkey"
echo ""

echo "  Contributing to phase 2 zkey..."
snarkjs zkey contribute \
  "$BUILD_DIR/kyc_eligibility_0000.zkey" \
  "$BUILD_DIR/kyc_eligibility_final.zkey" \
  --name="veil-kyc phase 2 contribution" \
  -e="random entropy for test only" -v
echo ""

# --- Step 5: Export verification key ---
echo "[6/6] Exporting verification key..."
snarkjs zkey export verificationkey \
  "$BUILD_DIR/kyc_eligibility_final.zkey" \
  "$BUILD_DIR/verification_key.json"
echo "  -> $BUILD_DIR/verification_key.json"
echo ""

# --- Step 6: Export Solidity verifier (optional, for reference) ---
# snarkjs zkey export solidityverifier \
#   "$BUILD_DIR/kyc_eligibility_final.zkey" \
#   "$BUILD_DIR/Verifier.sol"

echo "=== Trusted setup complete ==="
echo ""
echo "Artifacts in $BUILD_DIR/:"
echo "  kyc_eligibility.r1cs              — R1CS constraint system"
echo "  kyc_eligibility_js/*.wasm          — WASM witness generator"
echo "  kyc_eligibility_final.zkey         — proving key"
echo "  verification_key.json              — verification key"
echo "  pot_final.ptau                     — powers of tau (test only!)"
echo ""
echo "To generate a proof:"
echo "  snarkjs groth16 fullprove input.json \\"
echo "    $BUILD_DIR/kyc_eligibility_js/kyc_eligibility.wasm \\"
echo "    $BUILD_DIR/kyc_eligibility_final.zkey \\"
echo "    proof.json public.json"
echo ""
echo "To verify a proof:"
echo "  snarkjs groth16 verify \\"
echo "    $BUILD_DIR/verification_key.json \\"
echo "    public.json proof.json"
