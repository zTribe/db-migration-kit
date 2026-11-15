import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { createMigration } from "../src/index.js";

test("timestamp discovery allocates after the latest migration when the clock is behind", async () => {
  const directory = await mkdtemp(join(tmpdir(), "kit-create-migration-"));
  try {
    const config = { directory, discovery: "timestamp", files: ["20261116235959_previous.sql"] };
    const now = new Date("2026-11-15T19:00:00Z");
    const sql = "ALTER TABLE app.rooms ADD COLUMN vote_state smallint;";
    const file = await createMigration(config, "vote_state", sql, now);
    assert.equal(basename(file), "20261117000000_vote_state.sql");
    assert.equal(await readFile(file, "utf8"), sql + "\n");
    await assert.rejects(() => createMigration(config, "vote_state", sql, now), { code: "EEXIST" });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
