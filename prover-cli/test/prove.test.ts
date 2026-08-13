import test from "node:test";
import assert from "node:assert/strict";
import { prove } from "../src/prove.js";

test("prove stub throws not-implemented until Day 2", () => {
  assert.throws(
    () => prove("./attestation.json", "jurisdiction_not_in:sanctioned_list;accredited:true"),
    /not implemented/,
  );
});
