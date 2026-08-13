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
