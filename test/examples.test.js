import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const examples = resolve(root, "examples");

for (const [service, minimum] of [["indexer", 40], ["chat", 30]]) {
  test(`${service} example is a complete, ordered, project-specific manifest`, async () => {
    const config = JSON.parse(await readFile(resolve(examples, `${service}.migration-kit.config.json`), "utf8"));
    assert.ok(config.files.length >= minimum);
    assert.equal(new Set(config.files).size, config.files.length);
    assert.ok(config.files.every(file => typeof file === "string" && file.endsWith(".sql")));
    assert.ok(typeof config.directory === "string" && config.directory.length > 0);
    assert.ok(typeof config.lockName === "string" && config.lockName.length > 0);
  });
}

test("Chat example retains its app migration ledger", async () => {
  const config = JSON.parse(await readFile(resolve(examples, "chat.migration-kit.config.json"), "utf8"));
  assert.equal(config.schema, "app");
  assert.equal(config.ledgerTable, "schema_migrations");
  assert.equal(config.lockName, "ztribe-chat-schema-migrations");
});
