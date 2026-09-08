# Contributing

Thanks for your interest in veil-kyc! This project is an open-source
zero-knowledge compliance gate for Stellar/Soroban. This guide helps you get
oriented and find a good first task.

## Onboarding

To reproduce the full local flow, follow the README's **Getting Started** and
**Usage** sections. Only three documents are needed:

1. [`README.md`](./README.md) — the single source of truth for what the system
   is and how to run it.
2. [`docs/decisions.md`](./docs/decisions.md) — every place the implementation
   intentionally diverged from or clarified the README.
3. [`Plan.md`](./Plan.md) — the build plan and 65% milestone definition.

If you can produce a local eligibility proof and a gated transfer using only
those three documents, you're ready to contribute.

## Development setup

```bash
npm install            # issuer-service + prover-cli dependencies
cargo build --workspace --target wasm32v1-none --release  # contracts (from contracts/)
npm test               # JS/TS tests
cargo test --workspace # Rust contract tests (from contracts/)
```

## Tests

- **JS/TS:** `npm test` (runs both workspace test suites).
- **Contracts:** `cargo test --workspace` from `contracts/`. The
  `policy_gate/tests/integration.rs` suite runs the full
  issuer→prover→verifier→gate→transfer flow against the local Soroban test
  Env — no live network required.

## Where to start

A good starting task is the **first unclaimed item on the Roadmap**:

> **Browser-based proving (WASM) for non-technical end users**

Today the prover is a CLI (`prover-cli/`). The circuit already compiles to WASM
(`circuits/build/kyc_eligibility_js/kyc_eligibility.wasm`) and
`circomlibjs` is already a dependency, so a browser target builds on the
existing `buildCircuitInput` + `prove` pipeline rather than requiring new
infrastructure.

Before starting any Roadmap item, open an issue describing your proposed
approach so maintainers can coordinate.

## Guidelines

- Run `npm test` and `cargo test --workspace` before submitting.
- Keep the README and code in agreement: if implementation and documentation
  diverge, log the deviation in `docs/decisions.md` (and correct the README
  where it is factually wrong).
- Do not introduce new dependencies, contracts, or circuits that go beyond
  what the README already scaffolds.
- Follow the existing code style — match the surrounding files.

## License

By contributing you agree that your contributions are licensed under the
[MIT License](./LICENSE).
