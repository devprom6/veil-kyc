import test from "node:test";
import assert from "node:assert/strict";
import { buildCircuitInput, type Attestation } from "../src/build-input.js";

const SAMPLE_ATTESTATION: Attestation = {
  version: 1,
  user: "alice",
  attributes: { user: "alice", jurisdiction: "NG", accredited: true, sanctioned: false },
  commitment: "0x0fa04ec416130f6b43e8527bb9ea62fd3c873e4d403165f876bb8156e7ede732",
  issuer_pubkey: {
    x: "0x24240486bdeeac598fd7cfba3257ca436dd0bed77f0f809eeee433731c2c743f",
    y: "0x2b40cd4096a5c4593062811055b8a6835f554db65b52a4a83cfa5dcb2e29e4e8",
  },
  signature: {
    R8: {
      x: "0x2fd3f31aea0f09dfb41a7c72a0a9b2248e7a47aa99bb2a43be6bc8ab2b3ac742",
      y: "0x02e721964e29eeff46d0dc060e7e7763144d05a2439cf19ccf63683c7926bd2a",
    },
    S: "0x04e76c1e3bfb2edef043aec0d7945c9115745b4e7491baad086349d6a88c2553",
  },
  created_at: "2026-09-07T16:19:00.211Z",
};

test("buildCircuitInput derives valid policy-satisfying circuit input", async () => {
  const input = await buildCircuitInput(
    SAMPLE_ATTESTATION,
    "jurisdiction_not_in:sanctioned_list;accredited:true",
    "USDC-NG-2026-01-15",
  );

  assert.equal(input.attributes[2], "0x" + "0".repeat(63) + "1"); // accredited
  assert.equal(input.attributes[3], "0x" + "0".repeat(64)); // not sanctioned
  assert.equal(input.merkle_indices.length, 8);
  assert.equal(input.merkle_path.length, 8);
  assert.equal(input.signature.length, 3);
  assert.match(input.nullifier, /^0x[0-9a-f]{64}$/);
});

test("buildCircuitInput yields a distinct nullifier per context", async () => {
  const a = await buildCircuitInput(SAMPLE_ATTESTATION, "jurisdiction_not_in:sanctioned_list", "ctx-1");
  const b = await buildCircuitInput(SAMPLE_ATTESTATION, "jurisdiction_not_in:sanctioned_list", "ctx-2");
  assert.notEqual(a.nullifier, b.nullifier);
});
