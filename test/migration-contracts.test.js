import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyMigrationContracts } from "../src/testing.js";

test("project SQL contracts are validated through Kit without embedding project rules", async () => {
  const root = await mkdtemp(join(tmpdir(), "kit-contract-"));
  try {
    await mkdir(join(root, "migrations"));
    await writeFile(join(root, "migrations", "001_first.sql"), "create table app.example(id integer);\n");
    await writeFile(join(root, "config.json"), JSON.stringify({
      directory: "migrations", files: ["001_first.sql"], schema: "app", ledgerTable: "schema_migrations", lockName: "contract-test"
    }));
    const config = join(root, "config.json");
    assert.deepEqual(await verifyMigrationContracts(config, [{
      version: "001_first", required: [/create table app\.example/i], forbidden: [/grant all to public/i]
    }]), [{ version: "001_first", checked: 2 }]);
    await assert.rejects(verifyMigrationContracts(config, [{ version: "002_missing", required: [/create table/i] }]), /migration missing/);
    await assert.rejects(verifyMigrationContracts(config, [{ version: "001_first" }]), /must include assertions/);
    await assert.rejects(verifyMigrationContracts(config, [{ version: "001_first", required: [/drop table/i] }]), /required/);
    await assert.rejects(verifyMigrationContracts(config, [{ version: "001_first", forbidden: [/create table/i] }]), /forbidden/);
    await assert.rejects(verifyMigrationContracts(config, [{ version: "001_first", required: ["not-regexp"] }]), /RegExp/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
