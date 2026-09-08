# Architecture

This note describes the components and data flow of veil-kyc at the 65%
milestone (Day 5). It matches the "How It Works" and "Architecture" sections of
[`../README.md`](../README.md); where the implementation diverges from or
clarifies the README, the deviation is logged in
[`decisions.md`](./decisions.md).

## Components

| Component | Responsibility | Where it runs |
|---|---|---|
| **Issuer service** (`issuer-service/`) | Takes a user's attributes, computes a Poseidon commitment, signs it with a BabyJubJub EdDSA key, and writes a v1 attestation JSON. | Off-chain, operated by a licensed anchor/KYC provider |
| **Prover CLI** (`prover-cli/`) | Reads an attestation, derives the kyc_eligibility circuit input (Merkle root/path, nullifier, signature), runs snarkjs `groth16 fullprove`, and emits proof + public-input blobs in the verifier contract's byte format. | Off-chain, client-side |
| **Verifier contract** (`contracts/verifier/`) | Stores the Groth16 verification key and verifies a `BytesN<256>` proof against a flat `Bytes` blob of public inputs using Protocol 25 native BN254 pairing host functions. | Soroban, on-chain |
| **Policy gate contract** (`contracts/policy_gate/`) | Resolves the active policy, calls `verifier::verify_proof`, rejects replayed nullifiers, records the nullifier, and only then invokes the underlying SEP-41 transfer. | Soroban, on-chain |
| **Stablecoin demo** (`contracts/stablecoin_demo/`) | A SEP-41-compatible token that only moves value through the configured policy_gate address. | Soroban, on-chain |

The design keeps the verifier contract generic and reusable — any application
(stablecoin issuer, RWA marketplace, remittance corridor) can plug its own
policy contract on top of the same verifier.

## Data flow

1. The **issuer** performs KYC off-chain and produces a signed attestation:
   `{user, attributes, commitment, issuer_pubkey, signature, created_at}`. The
   commitment is `Poseidon(user, jurisdiction, accredited, sanctioned)`; the
   signature is EdDSA over that commitment. Nothing is published on-chain.

2. The **prover** converts the attestation plus a policy string
   (`jurisdiction_not_in:sanctioned_list;accredited:true`) into the circuit
   input. A deterministic demo attestation tree is reconstructed from the
   commitment (the reference prover's simplification — see
   `prover-cli/src/build-input.ts` and decisions.md Day 4). snarkjs generates a
   Groth16 proof.

3. The prover re-encodes the snarkjs output into the **verifier contract's byte
   format** (`prover-cli/src/soroban-blob.ts`): proof as a 256-byte blob
   (A‖B‖C), public inputs as N × 32-byte big-endian field elements, in the
   Ethereum alt_bn128 uncompressed layout used by Protocol 25.

4. `policy_gate::verify_and_transfer(proof, public_inputs, recipient, amount)`
   runs the gate-then-transfer sequence: load the default policy (fail closed
   if unset), call `verifier::verify_proof`, reject if the proof's nullifier was
   already spent, record the nullifier, and only then transfer `amount` from
   the gate's token holding to `recipient`.

## Sequence diagram

Matching README "How It Works" (issuer → prover → verifier → gate → transfer):

```
 User/Prover           Issuer          PolicyGate       Verifier        Token (SEP-41)
    │                    │                │                │                │
    │  get KYC + attest  │                │                │                │
    │───────────────────▶│                │                │                │
    │  attestation (signed commitment)    │                │                │
    │◀───────────────────│                │                │                │
    │                    │                │                │                │
    │  prove (off-chain) │                │                │                │
    │  build circuit input, run Groth16   │                │                │
    │                    │                │                │                │
    │  verify_and_transfer(proof, inputs, recipient, amount)                │
    │───────────────────────────────────▶│                │                │
    │                    │                │ verify_proof(proof, inputs)     │
    │                    │                │───────────────▶│                │
    │                    │                │  true (or false→fail)           │
    │                    │                │◀───────────────│                │
    │                    │                │                │                │
    │                    │                │  check nullifier not spent      │
    │                    │                │  record nullifier               │
    │                    │                │                │                │
    │                    │                │  transfer(from=gate, recipient) │
    │                    │                │────────────────────────────────▶│
    │                    │                │                │  balance moves  │
    │  Ok (or Err)       │                │                │                │
    │◀───────────────────│                │                │                │
```

The gate contract holds the disbursed balance and authorizes the token call as
its own address (`env.current_contract_address()`), so external callers cannot
move the gate's holding directly (see decisions.md Day 3).

## Byte-format bridge

snarkjs Groth16 output maps to Soroban's Protocol 25 BN254 host-function layout
by **pure byte re-packing** — no endian or base changes (decisions.md Day 4):

| snarkjs | Contract type | Layout |
|---|---|---|
| Fr public inputs | `fp32` | 32-byte big-endian field elements |
| G1 (`pi_a`, `pi_c`, VK `alpha`, IC) | `Bn254G1Affine` | 64 bytes `be(X)‖be(Y)` |
| G2 (`pi_b`, VK `beta`/`gamma`/`delta`) | `Bn254G2Affine` | 128 bytes `be(c1_X)‖be(c0_X)‖be(c1_Y)‖be(c0_Y)` (imaginary component first) |
| proof | `BytesN<256>` | `A‖B‖C` concatenated |

## Verification-key layout

`set_verification_key` takes the four Groth16 curve points plus a flat IC blob
(64 bytes per point). The public-signal order is fixed at
`[eligible, attestation_root, sanctioned_list_root, nullifier,
issuer_pubkey_x, issuer_pubkey_y]`, so the gate extracts the nullifier at
flat-blob offset `3 * 32` (`NULLIFIER_INDEX = 3` in policy_gate).
