# veil-kyc

**Zero-knowledge compliance for Stellar payments — prove you're allowed to transact, without revealing who you are.**

[![Stellar](https://img.shields.io/badge/Stellar-Soroban-brightgreen)](https://stellar.org)
[![Protocol](https://img.shields.io/badge/Protocol-25%20(X--Ray)-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-hackathon%20prototype-orange)]()

---

## Table of Contents

- [Overview](#overview)
- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Repo Structure](#repo-structure)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Circuit Design](#circuit-design)
- [Smart Contract Interface](#smart-contract-interface)
- [Security & Threat Model](#security--threat-model)
- [Compliance Model](#compliance-model)
- [Roadmap](#roadmap)
- [Why Stellar](#why-stellar)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Overview

**veil-kyc** is a zero-knowledge compliance gate for stablecoin and payment transactions on Stellar. It lets a user prove to a Soroban smart contract that they satisfy a compliance policy — e.g. "KYC'd by an approved issuer," "not on a sanctions list," "in an eligible jurisdiction," "accredited investor" — **without revealing their identity, their specific attributes, or which issuer verified them beyond what's necessary**.

This is built for Stellar specifically because Stellar is where real money moves: stablecoins, cross-border remittances, tokenized real-world assets, and institutional settlement. Those use cases all share the same unresolved tension — **regulators and counterparties need assurance of compliance, but users and institutions don't want to broadcast sensitive financial identity data on a public ledger.** veil-kyc resolves that tension using zero-knowledge proofs rather than trusted intermediaries or full transparency.

## The Problem

On-chain payment rails create a hard trade-off:

- **Full transparency** (plaintext KYC data, public transaction history) → compliant, but leaks sensitive personal and financial data to anyone watching the chain.
- **Full anonymity** (no compliance layer at all) → private, but unusable for regulated entities: anchors, RWA issuers, and institutional counterparties cannot legally transact with unverified parties.

Most "compliant" crypto rails today solve this by centralizing trust in a single custodian or KYC provider who sees everything. That reintroduces the exact single point of failure and surveillance risk that public ledgers were supposed to reduce.

## The Solution

veil-kyc separates **verification** from **disclosure**:

1. A user is verified once by a licensed issuer (an anchor, a KYC provider, a regulated institution).
2. The issuer signs a commitment to the user's attributes — it does not publish them.
3. When the user wants to transact, they generate a zero-knowledge proof that their (private) attested attributes satisfy the (public) policy required by the counterparty or contract.
4. A Soroban contract verifies the proof on-chain in a single call and gates the transaction accordingly.

No attribute values, no identity, and no issuer-side transaction history are ever revealed on-chain. Only a boolean outcome is: **eligible** or **not eligible**.

## How It Works

```
 ┌──────────────┐        1. KYC + attestation        ┌──────────────────┐
 │    User      │ ───────────────────────────────────▶│  Issuer / Anchor │
 │ (wallet)     │◀─────────────────────────────────── │ (licensed entity)│
 └──────┬───────┘   signed commitment to attributes    └──────────────────┘
        │
        │ 2. Generate ZK proof off-chain
        │    "I hold a valid signed commitment where
        │     jurisdiction ∉ sanctioned_list AND accredited = true"
        ▼
 ┌──────────────────────┐   3. Submit proof + public inputs   ┌───────────────────────┐
 │ Prover (local/CLI/   │ ────────────────────────────────────▶│ Soroban Verifier       │
 │ browser, Circom+     │                                       │ Contract (BN254/       │
 │ Groth16 / RISC Zero) │◀──────────────────────────────────── │ Poseidon precompiles)  │
 └──────────────────────┘   4. verified: true/false             └──────────┬─────────────┘
                                                                            │
                                                                 5. gate stablecoin transfer
                                                                            ▼
                                                                ┌───────────────────────┐
                                                                │ Payment / Transfer     │
                                                                │ Contract executes      │
                                                                └───────────────────────┘
```

**Key property:** the issuer, the counterparty, and any on-chain observer learn only that the policy was satisfied — never the underlying attributes, and never a persistent identifier linking this proof to the user's other transactions (each proof uses a fresh nullifier).

## Architecture

The system has four logical components:

| Component | Responsibility | Where it runs |
|---|---|---|
| **Issuer service** | Performs KYC, signs commitments to user attribute sets (Poseidon-hashed Merkle leaves) | Off-chain, operated by a licensed anchor/KYC provider |
| **Prover** | Builds the ZK proof that private attributes satisfy a public policy | Off-chain, client-side (CLI, browser, or mobile) |
| **Verifier contract** | Verifies the Groth16/UltraHonk proof on-chain using Stellar's native BN254 + Poseidon host functions | Soroban, on-chain |
| **Policy/gate contract** | Defines the eligibility policy per corridor/asset and calls the verifier before allowing a transfer | Soroban, on-chain |

This design deliberately keeps the verifier contract generic and reusable — any application (a stablecoin issuer, an RWA marketplace, a remittance corridor) can plug in its own policy contract on top of the same verifier.

## Repo Structure

```
veil-kyc/
├── circuits/                # Circom circuits for eligibility proofs
│   ├── kyc_eligibility.circom
│   ├── nullifier.circom
│   └── merkle_membership.circom
├── contracts/                # Soroban (Rust) smart contracts
│   ├── verifier/              # Wraps BN254/Poseidon proof verification
│   ├── policy_gate/            # Corridor/asset-specific eligibility policy
│   └── stablecoin_demo/         # Example SEP-41 token gated by policy_gate
├── issuer-service/            # Reference off-chain issuer for signing attestations
├── prover-cli/               # CLI + JS SDK for generating proofs client-side
├── scripts/                  # Deployment and setup scripts (testnet)
├── test/                     # Circuit, contract, and integration tests
├── docs/                     # Architecture notes, threat model, sequence diagrams
├── .env.example
├── LICENSE
└── README.md
```

## Tech Stack

- **Ledger / smart contracts:** [Stellar](https://stellar.org) / [Soroban](https://soroban.stellar.org), Protocol 25 ("X-Ray") native BN254 and Poseidon host functions
- **Proving system:** Circom + Groth16 (primary), with UltraHonk and RISC Zero zkVM proofs supported as alternate backends
- **Contract language:** Rust (`no_std`, Soroban SDK)
- **Prover tooling:** snarkjs / circom, WASM witness generation for browser-side proving
- **Issuer service:** Node.js/TypeScript reference implementation
- **Token standard:** SEP-41 (Soroban token interface) for the demo stablecoin

## Getting Started

### Prerequisites

- Rust + `cargo`, with the `wasm32-unknown-unknown` target
- [Soroban CLI](https://developers.stellar.org/docs/tools/developer-tools)
- Node.js ≥ 18
- Circom ≥ 2.1 and snarkjs

### Installation

```bash
git clone https://github.com/<your-org>/veil-kyc.git
cd veil-kyc

# install JS/TS dependencies (issuer service, prover CLI)
npm install

# build the Soroban contracts
cd contracts/verifier && cargo build --target wasm32-unknown-unknown --release
cd ../policy_gate && cargo build --target wasm32-unknown-unknown --release
cd ../stablecoin_demo && cargo build --target wasm32-unknown-unknown --release
```

### Compile circuits

```bash
cd circuits
circom kyc_eligibility.circom --r1cs --wasm --sym -o build/
snarkjs groth16 setup build/kyc_eligibility.r1cs pot_final.ptau build/kyc_eligibility_0000.zkey
```

### Deploy to Stellar testnet

```bash
soroban contract deploy \
  --wasm contracts/verifier/target/wasm32-unknown-unknown/release/verifier.wasm \
  --network testnet
```

Full deployment scripts are in `scripts/deploy_testnet.sh`.

## Usage

### 1. Issue an attestation (issuer side)

```bash
cd issuer-service
npm run attest -- --user <pubkey> --jurisdiction NG --accredited true --sanctioned false
```

This produces a signed, Poseidon-committed attestation returned to the user's wallet — no attribute values are published anywhere.

### 2. Generate a proof (user side)

```bash
cd prover-cli
npm run prove -- \
  --attestation ./my_attestation.json \
  --policy "jurisdiction_not_in:sanctioned_list;accredited:true"
```

Outputs `proof.json` and `public_inputs.json`.

### 3. Submit and verify on-chain

```bash
soroban contract invoke \
  --id <policy_gate_contract_id> \
  --network testnet \
  -- verify_and_transfer \
  --proof ./proof.json \
  --public_inputs ./public_inputs.json \
  --recipient <recipient_address> \
  --amount 1000
```

If the proof verifies and the policy is satisfied, the gated stablecoin transfer executes in the same call.

## Circuit Design

The core circuit (`kyc_eligibility.circom`) proves the following statement:

> "I know a set of attributes `A` and a valid issuer signature `σ` over `commit(A)`, such that `commit(A)` is a leaf in the issuer's published Merkle tree of valid attestations, and `A` satisfies public policy `P`, and I have not already used this attestation for this nullifier context."

Concretely, it enforces:

1. **Signature check** — the issuer's signature over the attribute commitment is valid (EdDSA over the Poseidon hash of the attribute set).
2. **Merkle membership** — the commitment is included in the issuer's current attestation tree (proves the attestation hasn't been revoked and belongs to a real issuance).
3. **Policy satisfaction** — arithmetic/comparison constraints over the private attributes match the public policy (e.g. jurisdiction not in a public sanctioned-list Merkle root; accredited flag equals 1).
4. **Nullifier** — a deterministic value derived from the attestation and a context string (e.g. corridor ID + day) is output publicly, preventing reuse of the same attestation to bypass per-period limits, without linking separate transactions to the same user.

Public inputs: policy parameters, sanctioned-list Merkle root, nullifier, issuer public key.
Private inputs: attribute values, attribute-set Merkle path, issuer signature.

## Smart Contract Interface

### `verifier` contract

```rust
pub fn verify_proof(
    env: Env,
    proof: BytesN<256>,
    public_inputs: Vec<BytesN<32>>,
) -> bool;
```

Thin wrapper around Soroban's native BN254 pairing and Poseidon host functions; stateless and reusable by any policy contract.

### `policy_gate` contract

```rust
pub fn set_policy(env: Env, admin: Address, policy_id: Symbol, params: PolicyParams);

pub fn verify_and_transfer(
    env: Env,
    proof: BytesN<256>,
    public_inputs: Vec<BytesN<32>>,
    recipient: Address,
    amount: i128,
) -> Result<(), Error>;

pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool;
```

`verify_and_transfer` calls `verifier::verify_proof`, checks the nullifier hasn't been spent for the relevant policy context, records it, and only then invokes the underlying SEP-41 token transfer.

## Security & Threat Model

**In scope / mitigated:**
- Replay of a valid attestation across multiple transactions beyond policy limits → prevented by context-bound nullifiers.
- Forged attestations → prevented by issuer signature verification inside the circuit.
- Tampering with policy parameters after proof generation → policy parameters are public circuit inputs, bound into the proof itself.
- Correlation of a user's transactions via their proof → each proof reveals only a fresh, context-scoped nullifier, not a persistent identifier.

**Explicitly out of scope for this prototype:**
- Compromise or misbehavior of the issuer itself (garbage-in-garbage-out; the system proves consistency with an attestation, not the truth of the underlying KYC check).
- Front-running or MEV on the settlement transaction itself.
- Side-channel deanonymization via network-level metadata (IP, timing) — proof generation should ideally happen client-side/locally, but this repo does not implement network-layer privacy.
- Formal audit of circuits or contracts — **this is hackathon/prototype code and has not been audited. Do not use with real funds.**

## Compliance Model

veil-kyc is designed to support, not replace, regulatory relationships:

- Issuers remain fully KYC/AML-compliant and retain off-chain records as required by their jurisdiction.
- An optional **auditor view key** mechanism can be layered in so a regulator, under appropriate legal process, can request the issuer decrypt a specific proof's linkage — the zero-knowledge property protects against *public* disclosure, not against lawful, targeted disclosure by the issuer who already holds the underlying data.
- Sanctioned-list membership is checked against a Merkle root that can be publicly updated by an authorized oracle/registry, keeping the policy itself auditable even though individual users' status stays private.

## Roadmap

- [x] Core eligibility circuit (jurisdiction, accreditation, sanctions check)
- [x] Soroban verifier contract using Protocol 25 BN254/Poseidon host functions
- [x] Reference issuer service and prover CLI
- [ ] Browser-based proving (WASM) for non-technical end users
- [ ] Multi-issuer support with a registry of trusted issuer public keys
- [ ] Per-corridor rolling-window compliance proofs (cumulative amount thresholds)
- [ ] Formal audit
- [ ] Mainnet pilot with a partner anchor

## Why Stellar

Stellar is where real money already moves — stablecoins, cross-border remittances, tokenized real-world assets, and institutional settlement. Compliance is not an edge case for these use cases, it's the primary constraint on adoption. Stellar's Protocol 25 ("X-Ray") upgrade added native BN254 pairing and Poseidon host functions to Soroban, making on-chain ZK proof verification fast and cheap enough to sit directly in a payment's critical path — which is what makes this project practical to build and deploy today rather than purely theoretical.

## Limitations

- This is a hackathon-stage prototype: circuits, contracts, and the issuer service are reference implementations, not production-hardened.
- Trusted setup for the Groth16 circuit uses a sample/test `.ptau` — a production deployment requires a proper multi-party trusted setup ceremony (or a switch to a transparent proving system).
- Gas/resource costs for on-chain verification, while low relative to naive re-execution, have not been benchmarked at scale in this repo.

## Contributing

Issues and pull requests are welcome. Please open an issue describing the proposed change before submitting a large PR. Run `npm test` and `cargo test` before submitting.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- Stellar Development Foundation, for the Protocol 25 ZK primitives that made this feasible
- Nethermind, for Soroban ZK verifier tooling and the RISC Zero integration
- The Circom, snarkjs, and Groth16 communities
