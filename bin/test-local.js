#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { checksumText, createMigration, loadMigrationConfig, resolveUpgradePrefix } from "../src/index.js";
import { randomUUID } from "node:crypto";
import { setTimeout } from "node:timers/promises";

const [mode, project, ref = "HEAD", output, migrationName, reason, checksPath] = process.argv.slice(2);
if (!["upgrade", "full", "snapshot", "prepare"].includes(mode) || !["chat", "indexer"].includes(project)) {
  throw new Error("Usage: db-migrate-kit-test <upgrade|full|snapshot|prepare> <chat|indexer> [base-ref] [output-or-candidate] [migration-name] [review-reason] [checks.sql]");
}
const base = mode !== "full"
  ? execFileSync("git", ["rev-parse", "--verify", "--end-of-options", ref + "^{commit}"], { encoding: "utf8" }).trim()
  : "";
const docker = (...args) => execFileSync("docker", args, { encoding: "utf8" }).trim();
const pattern = mode !== "full" ? "^PR migrations upgrade" :
  project === "chat" ? "^shared migration runner applies the full" : "^Indexer replays the full";
const file = project === "chat" ? "test/chat-migrate.integration.test.mjs" : "test/migration-runner.integration.mjs";
async function runFixture(extraEnv = {}) {
  const name = "ztribe-migration-" + randomUUID();
  docker("run", "--rm", "-d", "--name", name, "-e", "POSTGRES_PASSWORD=postgres", "-p", "127.0.0.1::5432", "postgres:17");
  try {
    for (let attempt = 0; ; attempt++) {
      if (spawnSync("docker", ["exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"]).status === 0) break;
      if (attempt === 59) throw new Error("Local PostgreSQL did not start");
      await setTimeout(500);
    }
    const port = docker("port", name, "5432/tcp").split(":").at(-1);
    if (!/^\d+$/.test(port)) throw new Error("Could not resolve the isolated PostgreSQL port");
    const url = `postgres://postgres:postgres@127.0.0.1:${port}/postgres`;
    const result = spawnSync(process.execPath, ["--test", "--test-name-pattern", pattern, file], {
      stdio: "inherit",
      env: { ...process.env, CHAT_TEST_DATABASE_URL: url, INDEXER_UPGRADE_DATABASE_URL: url,
        MIGRATION_UPGRADE_BASE_SHA: base, MIGRATION_SNAPSHOT_OUTPUT: mode === "snapshot" ? resolve(output ?? "before.json") : "", MIGRATION_LOCAL_FULL: mode === "full" ? "1" : "", MIGRATION_LOCAL_UPGRADE: mode === "upgrade" ? "1" : "",
        MIGRATION_CANDIDATE_CAPTURE: "", MIGRATION_PREPARE_CHECKS: "", ...extraEnv },
    });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`Migration fixture failed for ${project}`);
  } finally {
    docker("stop", name);
  }
}

if (mode !== "prepare") {
  await runFixture();
} else {
  if (!output || !/^[a-z][a-z0-9_]*$/.test(migrationName ?? "") || !reason?.trim() || !checksPath) {
    throw new Error("prepare requires candidate SQL path, migration name, review reason and checks.sql");
  }
  const configPath = resolve("db/migration-kit.config.json");
  const config = await loadMigrationConfig(configPath);
  const { pending } = await resolveUpgradePrefix(config, base, process.cwd());
  if (pending.length) throw new Error("Prepare on a baseline whose SQL matches the current migration directory");
  if (!config.requireMigrationGuards) throw new Error("Prepare requires a guarded migration config");

  const scratch = await mkdtemp(resolve(tmpdir(), "kit-prepare-"));
  let file;
  let sidecarWritten = false;
  try {
    const sql = (await readFile(resolve(output), "utf8")).trimEnd() + "\n";
    const source = resolve(scratch, "candidate.sql");
    const capture = resolve(scratch, "capture.json");
    const checks = resolve(scratch, "checks.sql");
    await writeFile(checks, await readFile(resolve(checksPath)));
    await writeFile(source, sql);
    await runFixture({
      MIGRATION_CANDIDATE_SQL: source,
      MIGRATION_CANDIDATE_CAPTURE: capture,
      MIGRATION_CANDIDATE_MODULE: new URL("./capture-candidate.js", import.meta.url).href,
    });
    const { before, after, digest } = JSON.parse(await readFile(capture, "utf8"));
    file = await createMigration(config, migrationName, sql);
    await writeFile(file + ".review.json", JSON.stringify({
      sqlChecksum: checksumText(sql), before, after, review: { digest, reason: reason.trim() },
    }, null, 2) + "\n", { flag: "wx" });
    sidecarWritten = true;
    await loadMigrationConfig(configPath);
    await runFixture({
      MIGRATION_LOCAL_UPGRADE: "1",
      MIGRATION_PREPARE_CHECKS: checks,
      MIGRATION_CANDIDATE_MODULE: new URL("./capture-candidate.js", import.meta.url).href,
    });
    console.log(file);
  } catch (error) {
    if (file) await rm(file, { force: true });
    if (sidecarWritten) await rm(file + ".review.json", { force: true });
    throw error;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
