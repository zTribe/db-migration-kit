#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout } from "node:timers/promises";

const [mode, project, ref = "HEAD"] = process.argv.slice(2);
if (!["upgrade", "full"].includes(mode) || !["chat", "indexer"].includes(project)) {
  throw new Error("Usage: db-migrate-kit-test <upgrade|full> <chat|indexer> [base-ref]");
}
const base = mode === "upgrade"
  ? execFileSync("git", ["rev-parse", "--verify", "--end-of-options", ref + "^{commit}"], { encoding: "utf8" }).trim()
  : "";
const name = "ztribe-migration-" + randomUUID();
const docker = (...args) => execFileSync("docker", args, { encoding: "utf8" }).trim();
const pattern = mode === "upgrade" ? "^PR migrations upgrade" :
  project === "chat" ? "^shared migration runner applies the full" : "^Indexer replays the full";
const file = project === "chat" ? "test/chat-migrate.integration.test.mjs" : "test/migration-runner.integration.mjs";
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
      MIGRATION_UPGRADE_BASE_SHA: base, MIGRATION_LOCAL_FULL: mode === "full" ? "1" : "", MIGRATION_LOCAL_UPGRADE: mode === "upgrade" ? "1" : "" },
  });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  docker("stop", name);
}
