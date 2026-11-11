import test from "node:test";
import assert from "node:assert/strict";
import { checksumText } from "../src/checksum.js";

test("checksum is stable SHA-256 and changes when SQL changes", () => {
  assert.equal(checksumText("select 1"), checksumText("select 1"));
  assert.notEqual(checksumText("select 1"), checksumText("select 2"));
  assert.match(checksumText("select 1"), /^[a-f0-9]{64}$/);
});
