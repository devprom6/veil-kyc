#!/usr/bin/env bash
# verify_toolchain.sh
#
# Verifies the toolchains listed in README "Prerequisites":
#   Rust + wasm32 target, Soroban CLI, Node >= 18, Circom >= 2.1, snarkjs
#
# Read-only: checks presence/version and prints install hints. It never
# installs anything.
set -uo pipefail

missing=0

ok()   { printf '  [ok]   %s\n' "$1"; }
miss() { printf '  [MISS] %s\n' "$1"; missing=1; }

echo "veil-kyc toolchain check"

# Node.js >= 18
if command -v node >/dev/null 2>&1; then
  major=$(node --version | sed 's/^v//' | cut -d. -f1)
  if [ "$major" -ge 18 ]; then ok "node >= 18 ($(node --version))"; else miss "node >= 18 (found $(node --version))"; fi
else
  miss "node (https://nodejs.org)"
fi

# npm
command -v npm >/dev/null 2>&1 && ok "npm ($(npm --version))" || miss "npm"

# Rust + cargo
command -v rustc >/dev/null 2>&1 && ok "rustc ($(rustc --version))" || miss "rustc (https://rustup.rs)"
command -v cargo >/dev/null 2>&1 && ok "cargo ($(cargo --version))" || miss "cargo"

# wasm32 targets
installed=$(rustup target list --installed 2>/dev/null)
case "$installed" in
  *wasm32v1-none*) ok "wasm32v1-none target (Soroban on Rust >= 1.82)" ;;
  *) miss "wasm32v1-none target (rustup target add wasm32v1-none)" ;;
esac
case "$installed" in
  *wasm32-unknown-unknown*) ok "wasm32-unknown-unknown target" ;;
  *) miss "wasm32-unknown-unknown target (rustup target add wasm32-unknown-unknown)" ;;
esac

# Soroban CLI
if command -v soroban >/dev/null 2>&1; then
  ok "soroban ($(soroban --version 2>&1 | head -1))"
else
  miss "soroban CLI (https://github.com/stellar/stellar-cli)"
fi

# circom >= 2.1
if command -v circom >/dev/null 2>&1; then
  ok "circom ($(circom --version 2>&1 | head -1))"
else
  miss "circom >= 2.1 (build from https://github.com/iden3/circom)"
fi

# snarkjs
if command -v snarkjs >/dev/null 2>&1; then
  ok "snarkjs ($(snarkjs --version 2>&1 | head -1))"
else
  miss "snarkjs (npm install -g snarkjs)"
fi

echo
if [ "$missing" -eq 0 ]; then
  echo "All toolchains present."
else
  echo "Some toolchains are missing (see [MISS] above). Nothing was installed."
fi
exit "$missing"
