import test from "node:test";
import assert from "node:assert/strict";
import { assertManagedTransaction } from "../src/transaction-sql.js";

test("detects top-level transaction commands without matching procedural bodies or strings", () => {
  for (const command of ["BEGIN", "START TRANSACTION", "COMMIT", "END", "ROLLBACK", "ABORT",
    "SAVEPOINT s", "RELEASE s", "PREPARE TRANSACTION 'x'", "SET TRANSACTION READ ONLY"]) {
    assert.throws(() => assertManagedTransaction(`SELECT 1; /* nested /* comment */ */ ${command};`, "test"),
      /leave transaction control to Kit/);
  }
  assert.doesNotThrow(() => assertManagedTransaction(
    "DO $body$ BEGIN RAISE NOTICE 'COMMIT'; END $body$; SELECT 'ROLLBACK;'; -- COMMIT", "test",
  ));
});
