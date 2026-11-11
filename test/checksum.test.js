import test from "node:test";
import assert from "node:assert/strict";
import { checksumText } from "../src/checksum.js";

test("checksum is stable SHA-256 and changes when SQL changes", () => {
  assert.equal(checksumText("select 1"), checksumText("select 1"));
  assert.notEqual(checksumText("select 1"), checksumText("select 2"));
  assert.match(checksumText("select 1"), /^[a-f0-9]{64}$/);
});

import { mkdtemp, writeFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadManifest } from "../src/checksum.js";

test("manifest rejects unordered, duplicate and path-escaping entries", async () => {
  const dir = await mkdtemp(join(tmpdir(), "kit-manifest-"));
  const outside = await mkdtemp(join(tmpdir(), "kit-outside-"));
  try {
    await writeFile(join(dir, "001_first.sql"), "select 1;");
    await writeFile(join(dir, "002_second.sql"), "select 2;");
    await writeFile(join(outside, "secret.sql"), "select 3;");
    await symlink(join(outside, "secret.sql"), join(dir, "003_link.sql"));
    await assert.rejects(() => loadManifest({ directory: dir, files: ["002_second.sql", "001_first.sql"] }), /not strictly ordered/);
    await assert.rejects(() => loadManifest({ directory: dir, files: ["001_first.sql", "001_first.sql"] }), /duplicate/);
    await assert.rejects(() => loadManifest({ directory: dir, files: ["../secret.sql"] }), /invalid migration/);
    await assert.rejects(() => loadManifest({ directory: dir, files: ["003_link.sql"] }), /escapes directory/);
    const manifest = await loadManifest({ directory: dir, files: ["001_first.sql", "002_second.sql"] });
    assert.equal(manifest.length, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
