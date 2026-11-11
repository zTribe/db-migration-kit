import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifest } from "../src/index.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const examples = resolve(root, "packages/db-migration-kit/examples");

test("Indexer CLI example references the complete checked-in SQL manifest", async () => {
  const config = JSON.parse(await readFile(resolve(examples, "indexer.migration-kit.config.json"), "utf8"));
  const migrations = await loadManifest({ ...config, directory: resolve(root, config.directory) });
  assert.equal(migrations.length, config.files.length);
  assert.ok(migrations.length >= 40);
});

test("Chat CLI example is a valid ordered manifest with its own app ledger", async () => {
  const config = JSON.parse(await readFile(resolve(examples, "chat.migration-kit.config.json"), "utf8"));
  assert.equal(config.schema, "app");
  assert.equal(config.ledgerTable, "schema_migrations");
  assert.equal(config.lockName, "ztribe-chat-schema-migrations");
  assert.ok(config.files.length >= 30);
  assert.equal(new Set(config.files).size, config.files.length);
  assert.ok(config.files.every(file => file.endsWith(".sql")));
});
