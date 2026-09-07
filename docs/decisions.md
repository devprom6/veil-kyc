# Implementation Decisions

One-line entries for judgment calls / deviations from README.md. Per the Day 1
brief: when README.md is ambiguous or silent on an implementation detail, make
the smallest reasonable choice consistent with the rest of the document and log
it here — do not silently expand scope.

## Day 1

- Toolchains verified present: Node 24, npm 11, Rust 1.96, wasm32-unknown-unknown + wasm32v1-none targets, snarkjs 0.7.6. circom and the Soroban CLI are NOT installed (per operator instruction) — circuit compilation (`circom --r1cs`) and on-chain deploy verification are deferred.
- `contracts/Cargo.toml` is a workspace over verifier/policy_gate/stablecoin_demo (README's Getting Started builds each contract in turn; a workspace keeps `cargo build`/`cargo test` ergonomic). README's tree does not list it — logged here.
- soroban-sdk pinned `=25.3.2` (latest self-consistent 25.x, Protocol 25 "X-Ray"). `=25.0.0` is the mainnet-aligned release but its `soroban-sdk-macros` dep range resolves to 25.3.x, which generates `IntoValForContractFn` — absent in SDK 25.0.0 — so it fails to compile.
- Contract wasm target is `wasm32v1-none`, not README's `wasm32-unknown-unknown`: soroban-sdk 25's build script rejects `wasm32-unknown-unknown` on Rust ≥1.82 (reference-types/multi-value), and this machine has Rust 1.96.
- `PolicyParams { sanctioned_list_root, require_accredited }` is a provisional shape (README names the type but never defines it); grounded in README's described policy (sanctioned-list root + accredited flag).
- verifier `verify_proof` keeps README's exact signature (`BytesN<256>` proof, `Vec<BytesN<32>>` public inputs); in soroban-sdk 25 `BytesN<N>` is N bytes, so proof=256B, inputs=32B — consistent with Groth16.
- Contract stubs fail closed (verify_proof→false, verify_and_transfer→Err, is_nullifier_used→false); no policy/verification logic until Days 2-3.
- `circuits/kyc_eligibility.circom` written to circom 2.1 syntax with a placeholder constraint (`1 * 1 === 1`) so the skeleton yields a valid r1cs; `circom --r1cs` verification is deferred because circom is not installed (per operator instruction).
- Circuit placeholder sizes: attributes=4 (`[user, jurisdiction, accredited, sanctioned]`), merkle_path=8 (issuer attestation tree depth), signature=3 (`[R.x, R.y, S]`); will be re-derived when enforcement lands on Day 2.
- Added public `eligible` output signal to the circuit: README says on-chain only a boolean "eligible / not eligible" is revealed, and Groth16 outputs are public signals.
- issuer-service uses `circomlibjs@0.1.7`, which exposes only async builders (`buildPoseidon()`, `buildEddsa()`); its field elements are `Uint8Array` subclasses, so the EdDSA message is passed as `eddsa.F.e(commitment)` and signature uses `signPoseidon`/`verifyPoseidon` (the Poseidon-hash variant that the Day 2 circom `eddsaposeidon` template matches).
- Attribute commitment is `Poseidon([user, jurisdiction, accredited, sanctioned])`; strings are encoded as field elements via Poseidon over their UTF-8 bytes (31-byte chunks to stay below the BN254 field order).
- Dev issuer key: if `ISSUER_PRIVATE_KEY` is unset, a random key is generated and persisted to `issuer-service/.dev/issuer_key.json` (gitignored) so attestations are reproducible across runs without hardcoding secrets.
- Attestation JSON schema (v1): `{version, user, attributes, commitment, issuer_pubkey{x,y}, signature{R8{x,y},S}, created_at}` — all field values as 64-hex-char `0x` strings.
- `scripts/verify_toolchain.sh` added as the setup script (README's `scripts/` is "Deployment and setup scripts"); it verifies the README prerequisites and prints install hints but never installs anything.
- End of Day 1 status: folder structure matches README exactly; `npm install && npm run attest -- --user test --jurisdiction NG --accredited true --sanctioned false` works end-to-end; `cargo build --workspace --target wasm32v1-none --release` and `npm test` / `cargo test --workspace` pass. The DoD item `circom circuits/kyc_eligibility.circom --r1cs -o build/` is **unverified** — circom is not installed (per operator instruction), so compiling the skeleton is deferred to Day 2.

## Day 2

- circom 2.2.3 installed from source (`cargo install --git https://github.com/iden3/circom`); not on crates.io.
- circomlib circuits vendored to `circuits/vendor/circomlib/` (git-tracked). Compiled circuits use `-l circuits/vendor/circomlib -l circuits` to resolve includes; circomlib's internal includes (e.g. `poseidon.circom` → `poseidon_constants.circom`) resolve relative to the vendor directory.
- Circuit public inputs expanded from Day 1 scaffold: `policy_root` renamed to `attestation_root` (the Merkle root of the issuer's attestation tree, needed for membership verification); `issuer_pubkey` split into `issuer_pubkey_x` / `issuer_pubkey_y` (EdDSAPoseidonVerifier takes `Ax, Ay` separately). Total public inputs: 5.
- Added `merkle_indices[8]` as a private input (Day 1 scaffold only had `merkle_path[8]`); the prover must supply path direction bits at each Merkle level.
- Added `context` as a private input for the nullifier; the circuit constrains `nullifier == Poseidon(commitment, context)` against the public nullifier input.
- Jurisdiction-not-sanctioned check uses a field-element inequality (`attributes[1] != sanctioned_list_root`). This is sound for single-entry sanctioned lists where `root = field_element(jurisdiction_code)`. A production implementation should use Merkle non-membership proofs — logged here as a known hackathon simplification.
- `eligible` output is always `1` for any valid witness (all constraints must pass for a witness to exist). The output is redundant but explicit per README's "only a boolean eligible/not eligible is revealed on-chain."
- Compiled circuit: 9891 non-linear constraints, 247 template instances, 5 public inputs, 24 private inputs, 1 public output.
- Verifier contract `verify_proof` public inputs changed from `Vec<BytesN<32>>` to flat `Bytes` (N × 32 bytes): Soroban contract functions do not support generic type parameters on user-defined types (`Vec<BytesN<32>>` → compile error "generics unsupported on user-defined types"). Logged as an interface deviation from README; README will need updating.
- Verifier contract stores the Groth16 verification key in instance storage via `set_verification_key(alpha_g1, beta_g2, gamma_g2, delta_g2, ic_flat, ic_count)`. The IC points are packed into a flat `Bytes` blob (64 bytes each) because `Vec<BytesN<64>>` has the same Soroban generics limitation.
- Groth16 pairing equation: `e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1_T`, implemented using `env.crypto().bn254().pairing_check(Vec<Bn254G1Affine>, Vec<Bn254G2Affine>)`.
- Trusted setup uses `snarkjs powersoftau new bn128 14` (2^14 = 16384 constraint capacity, sufficient for 9891 non-linear constraints). Test-only `.ptau` and `.zkey` in `circuits/build/` (gitignored). Production requires a multi-party ceremony.
- Test input generation (`test/generate_inputs.ts`) builds a Poseidon Merkle tree of 4 attestation commitments (8 levels), signs with a random EdDSA key, and produces 4 input files: valid (NG/accredited), invalid_signature, invalid_accredited, invalid_sanctioned (KP).
- Test results: valid proof generates and verifies off-chain; all 3 invalid cases correctly fail at witness generation (assert failures at EdDSA verifier line 70 or jurisdiction constraint line 106).
- End of Day 2 status: circuit compiles, all four constraint properties enforced, local Groth16 proof verified off-chain, verifier contract builds to wasm and passes unit tests.

## Day 3

- policy_gate `verify_and_transfer` public inputs are flat `Bytes` (N × 32), not README's `Vec<BytesN<32>>` — same Soroban generics limitation as the Day 2 verifier deviation (line 37). The gate forwards the blob verbatim to `verifier::verify_proof`.
- `verify_and_transfer` has no `policy_id` in README, yet `set_policy` registers per corridor/asset. Selected a **single active (default) policy** model (operator-confirmed): the most recent `set_policy` becomes the default that `verify_and_transfer` enforces, so README's entry points are unchanged. Multi-policy/multi-corridor routing is a natural Roadmap extension.
- `PolicyParams` extended with `verifier` and `token` `Address` fields (operator-confirmed). The README signature has no way to pass these per call; carrying them in the policy params keeps the interface identical while letting one gate target any verifier + SEP-41 token.
- Nullifier storage is keyed by the 32-byte nullifier alone, not `(policy_id, nullifier)`. This is context-scoped by construction: the circuit constrains `nullifier == Poseidon(commitment, context)`, so distinct contexts produce distinct nullifiers.
- The gate contract holds the disbursed SEP-41 balance and `verify_and_transfer` transfers `from = env.current_contract_address()`. No `from` appears in README's signature; the gate authorizing as itself is the only way the token's `from.require_auth()` can pass for the gate's holding. The gate's holding is funded by admin mint.
- Groth16 public-signal ordering: the kyc_eligibility circuit's 6 public signals are `[eligible, attestation_root, sanctioned_list_root, nullifier, issuer_pubkey_x, issuer_pubkey_y]`, so the gate extracts the nullifier at flat-blob offset `3 * 32` (constant `NULLIFIER_INDEX = 3` in policy_gate). This is a demo convenience: `verifier::verify_proof` already validated the proof against the same inputs end-to-end, so the gate trusts the blob structure once verification passes.
- stablecoin_demo stores its symbol as `String`, not `Symbol`: SEP-41's `symbol()` returns `String`, and `Symbol::to_string` is only available on non-wasm targets.
- stablecoin_demo is SEP-41-compatible by function signature (callable via `soroban_sdk::token::TokenClient`), matching the canonical Soroban example token pattern, rather than `impl TokenInterface for …` (which would double-register the entry points).
- Gate-only token: `transfer`/`transfer_from`/`burn`/`burn_from` require the source to be the configured `gate` address (`require_gate_source`) plus standard `from.require_auth()`. Tokens minted to the gate therefore can only leave the gate's balance through `policy_gate::verify_and_transfer`; a plain holder's own balance move is blocked by the gate-source check.
- policy_gate unit tests and the `policy_gate/tests/integration.rs` integration test register a tiny local **mock verifier** with the same `verify_proof(proof: BytesN<256>, public_inputs: Bytes) -> bool` signature and a configurable verdict. Real Groth16 verification is covered by circuits + verifier on Day 2; the Day 3 tests exercise gate logic (nullifier replay, ordering, token invocation) locally without a live network.
- Contract clients generated by `#[contractimpl]` unwrap `Result<(), Error>` and panic on error, so tests assert via the generated `try_verify_and_transfer(...) -> Result<Result<(), ConversionError>, Result<Error, InvokeError>>` shape.
- `Env::register_contract` is deprecated in SDK 25.3.2; tests use `env.register(C, ())`.
- `.gitignore` generalized to `contracts/*/test_snapshots/` (policy_gate tests also emit host-invocation snapshots).
- End of Day 3 status: all three contracts build to wasm (`cargo build --workspace --target wasm32v1-none --release`), `cargo test --workspace` passes, and the integration test demonstrates the full gate-then-transfer DoD locally (valid proof → transfer; replay → reject; invalid proof → reject).

## Day 4

- Encoding bridge resolved (the flagged integration friction point): snarkjs output maps to Soroban's Protocol 25 BN254 host-function byte layout with **no endian/base changes — it is pure byte re-packing**:
  - Fr public inputs → 32-byte big-endian field elements (`fp32`), matched to `Fr::from_bytes` (which reduces via `From<U256>`).
  - G1 (`proof.pi_a`, `pi_c`, VK `vk_alpha_1`, each `IC`) → 64 bytes `be(X) || be(Y)`.
  - G2 (`proof.pi_b`, VK `vk_beta_2`/`gamma_2`/`delta_2`) → 128 bytes `be(c1_X)||be(c0_X)||be(c1_Y)||be(c0_Y)` — each Fp2 coordinate is stored imaginary-component-first, matching soroban-sdk `crypto/bn254.rs` ("Fp2 element encoding: `be_bytes(c1) || be_bytes(c0)`").
  - Points are the Ethereum alt_bn128 precompile **uncompressed** encoding; top two flag bits unset.
- snarkjs proof points are affine `[x, y]` (2 elements); snarkjs VK points are projective `[x, y, z=1]` (3 elements). The encoder accepts both tuple shapes and ignores the redundant affine `z`.
- Public-signal order is fixed at [ eligible(output), attestation_root, sanctioned_list_root, nullifier, issuer_pubkey_x, issuer_pubkey_y ] (verified against `kyc_eligibility.sym`), so the nullifier sits at flat-blob offset `3 * 32`, consistent with policy_gate's `NULLIFIER_INDEX = 3`.
- Implementation is a library (`prover-cli/src/soroban-blob.ts`) with a semantic unit test against the real `circuits/build/{proof,public,verification_key}.json` artifacts, so the on-chain-format guarantee is continuously checked, not one-off.
- Toolchain this day: `stellar` CLI **28.0.0** (formerly `soroban` CLI; replaces the README's `soroban contract [...]` commands verbatim — same flags, new binary name). README Usage §3 rendered with `stellar contract invoke`.
- Type-encoding work committed first (before the deployment/prove integration) so both the deploy script (`vk2blob`) and the prover CLI share one, tested encoder.
