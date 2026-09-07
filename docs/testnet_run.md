# Testnet End-to-End Run

**Date:** 2026-09-07
**Network:** Stellar **testnet** (SDF Test Network ; September 2015)
**Tooling:** `stellar` CLI 28.0.0, `snarkjs` 0.7.6, circom 2.2.3

This documents a single successful, real, policy-gated transfer on Stellar
testnet, driven entirely through the README "Usage" commands:
issuer attests → prover proves → verifier verifies → token transfers.

## Contract deployments

Deployed and initialized on testnet by `scripts/deploy_testnet.sh`; IDs
recorded in `scripts/testnet_addresses.json`.

| Contract        | ID |
|---|---|
| verifier        | `CCCEIKEUELT3MVIPCA3JUUH5C2NMTCBXG7BKM4X6NOEVNQX7YSILTNFV` |
| policy_gate     | `CDGCFKACOZC2S77Y3JAYT2M4IH56SRUMEBHCFIX26PA4SGZ4FIM63BWF` |
| stablecoin_demo | `CDENH4YF2MTDVELIG6QIH22WCXDYC6AZE23KF6H2HZRK2FRKA7WB3L4U` |

Setup state applied on-chain:

- **verifier** — Groth16 verification key (6 public signals + constant IC)
  registered via `set_verification_key`.
- **stablecoin** — `initialize(deployer, "Veil Demo USD", "VDUSD", 7, gate)`;
  1,000,000 VDUSD minted to the gate.
- **policy_gate** — `set_policy(USDC_NG)` with `sanctioned_list_root =
  0216cbd5…fa8a` (the "KP" jurisdiction field element), `require_accredited =
  true`, pointing at the verifier and token above.

## The verified transaction (DoD)

The exact README Usage commands (#1 issuer attest, #2 prover prove, #3
`validate_and_transfer` via `stellar contract invoke`) were run against
testnet via `scripts/run_e2e.sh`.

- **issuer:** `npm run attest -- --user alice --jurisdiction NG --accredited true --sanctioned false`
- **prover:** `npm run prove -- --attestation <att> --policy "jurisdiction_not_in:sanctioned_list;accredited:true"`
- **on-chain:** `stellar contract invoke --id <gate> -- verify_and_transfer --proof <hex> --public_inputs <hex> --recipient <recipient> --amount 1000`

### Transaction

| Field | Value |
|---|---|
| **Transaction hash** | `41909e219419b0ed9ce121d1112e272cf2c2bd0564e8ce2c47cd95e7e958be85` |
| **Status** | `successful: true` |
| **Ledger** | 4555156 |
| **Created** | 2026-09-07T16:42:47Z |
| **Result** | `verify_and_transfer` → `Ok(())` (unit); `TransferEvent` emitted on the token: gate → recipient, amount `1000` |
| **Explorer** | https://stellar.expert/explorer/testnet/tx/41909e219419b0ed9ce121d1112e272cf2c2bd0564e8ce2c47cd95e7e958be85 |

### Flow details

| Step | Actor | Action | Outcome |
|---|---|---|---|
| 1 | issuer-service | Poseidon-commit + EdDSA-sign alice's attributes | attestation JSON |
| 2 | prover-cli | snarkjs `groth16 fullprove` with the trusted-setup artifacts | `proof.json`, `public_inputs.json`, plus verifier-format blob files |
| 3 | verifier contract | `verify_proof` (real pairing check, not a mock) | `true` |
| 4 | policy_gate | nullifier check → record → token transfer | `Ok(())`; transfer 1000 VDUSD gate → recipient |
| 5 | policy_gate | `is_nullifier_used` | `true` |

- **recipient:** `GCQQ2RSPG6JZSDILOPYPYZEKWFAQQJM4DVGIZPLI22L5ZQEPFITA7GFP`
- **spent nullifier:** `2235b76605e4e66dd2d665a825ba43a3afd469808d4a24a58785e9ccec39bceb`
  (public-signal index 3, i.e. byte offset `3 * 32` in the public-inputs blob)
- **transfer event:** token `CDENH4YF2MTD…L4U`, from `CDGCFKACOZC2…BWF` (gate) to
  `GCQQ2RSPG6…7GFP`, amount `1000`.

## Supporting setup transactions (for completeness)

| Action | Transaction hash |
|---|---|
| verifier deploy | `e4358c3146c1621bd7190d51a9a7927cad1b66bc174762dd899046ec3756567f` |
| verifier `set_verification_key` | `287e3f847218662d3b9336ab30dbf5711da52785fcbf2383f07aa30746d14231` |
| stablecoin `initialize` + mint | see `scripts/testnet_addresses.json` (idempotent deploy script) |

> Note: during this session the verifier was first validated against a
> real generated proof directly (`verify_proof` returned `true` on-chain)
> before wiring the full gate flow, de-risking the encoding bridge.

## Definition of Done — confirmed

Running the README "Usage" commands in order against testnet produces a
successful transfer, and `is_nullifier_used` returns `true` afterward.
✅
