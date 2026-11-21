#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { checksumText, createMigration, loadMigrationConfig, resolveUpgradePrefix } from "../src/index.js";
import { randomUUID } from "node:crypto";
import { setTimeout } from "node:timers/promises";
import { checkAiMigrationDraft } from "../src/ai-draft-check.js";
import { explainPrepareFailure } from "../src/prepare-errors.js";

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
const safeTestEnvironment = extras => {
  const safe={...process.env};
  for(const key of [
    "DATABASE_URL","MIGRATION_DATABASE_URL","CHAT_MIGRATION_DATABASE_URL",
    "CHAT_MIGRATION_DATABASE_URL_DIRECT","CHAT_DATABASE_URL","CHAT_DB_URL",
    "INDEXER_DATABASE_URL","INDEXER_DATABASE_URL_DIRECT","INDEXER_TEST_DATABASE_URL",
    "INDEXER_UPGRADE_DATABASE_URL","CHAT_TEST_DATABASE_URL",
    "MAIN_MIGRATION_AUDIT_DATABASE_URL","SUPABASE_DB_URL","SUPABASE_DATABASE_URL",
    "PGHOST","PGHOSTADDR","PGPORT","PGUSER","PGPASSWORD","PGDATABASE",
    "PGSERVICE","PGSERVICEFILE","PGPASSFILE","PGSSLMODE","PGSSLCERT","PGSSLKEY",
    "PGSSLROOTCERT","MIGRATION_CANDIDATE_NAME","MIGRATION_CANDIDATE_CAPTURE",
    "MIGRATION_CANDIDATE_SQL","MIGRATION_PREPARE_CHECKS","MIGRATION_CANDIDATE_MODULE"
  ]) delete safe[key];
  return {...safe,...extras};
};
export function confirmTargetedFixtureRan(output, project) {
  const tests=/# tests\s+(\d+)\b/.exec(output);
  const passed=/# pass\s+(\d+)\b/.exec(output);
  const failed=/# fail\s+(\d+)\b/.exec(output);
  if(!tests||!passed||!failed||Number(tests[1])===0||Number(passed[1])===0||Number(failed[1])!==0)
    throw Error("Migration fixture for "+project+" did not execute and pass any targeted tests; check --test-name-pattern and skip guards");
}

async function runFixture(extraEnv = {}) {
  const name = "ztribe-migration-" + randomUUID();
  let started = false;
  docker("run", "--rm", "-d", "--name", name, "-e", "POSTGRES_PASSWORD=postgres",
    "-p", "127.0.0.1::5432", "postgres:17");
  started = true;
  try {
    for (let attempt = 0; ; attempt++) {
      if (spawnSync("docker", ["exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"]).status === 0) break;
      if (attempt === 59) throw new Error("Local PostgreSQL did not start");
      await setTimeout(500);
    }
    const port = docker("port", name, "5432/tcp").split(":").at(-1);
    if (!/^\d+$/.test(port)) throw new Error("Could not resolve the isolated PostgreSQL port");
    const url = "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres";
    const env=safeTestEnvironment({
      CHAT_TEST_DATABASE_URL:url, INDEXER_UPGRADE_DATABASE_URL:url,
      MIGRATION_UPGRADE_BASE_SHA:base,
      MIGRATION_SNAPSHOT_OUTPUT:mode==="snapshot"?resolve(output??"before.json"):"",
      MIGRATION_LOCAL_FULL:mode==="full"?"1":"",
      MIGRATION_LOCAL_UPGRADE:mode==="upgrade"?"1":"",
      MIGRATION_CANDIDATE_CAPTURE:"",MIGRATION_PREPARE_CHECKS:"",
      ...extraEnv
    });
    const result=spawnSync(process.execPath, ["--test","--test-reporter=tap",
      "--test-name-pattern",pattern,file], {
      encoding:"utf8",maxBuffer:16*1024*1024,env
    });
    if(result.stdout)process.stdout.write(result.stdout);
    if(result.stderr)process.stderr.write(result.stderr);
    if(result.error)throw result.error;
    if(result.status!==0)throw Error("Migration fixture failed for "+project+"; exit="+(result.status??result.signal)+"\n"+
      (result.stderr??"").slice(-2000)+"\n"+(result.stdout??"").slice(-2500));
    confirmTargetedFixtureRan(result.stdout??"",project);
  } finally {
    if(started)docker("stop",name);
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

  let phase="initialization";
  const scratch = await mkdtemp(resolve(tmpdir(), "kit-prepare-"));
  let file;
  let sidecarWritten = false;
  try {
    phase="candidate-validation";
    const sql = (await readFile(resolve(output), "utf8")).trimEnd() + "\n";
    if (resolve(output).startsWith(resolve(config.directory) + "/"))
      throw Error("Candidate SQL must remain outside db/migrations until prepare succeeds");
    const ownerConfig = JSON.parse(await readFile(resolve("db/owner-maintenance-policy.json"),"utf8"));
    const draft = await checkAiMigrationDraft({name:migrationName,sql,ownerConfig});
    console.log(JSON.stringify({stage:"draft-check",...draft},null,2));
    if (!draft.ok) throw Error("AI draft-check failed; correct candidate and Owner recipe before PG17 prepare");

    const source = resolve(scratch, "candidate.sql");
    const capture = resolve(scratch, "capture.json");
    const checks = resolve(scratch, "checks.sql");
    await writeFile(checks, await readFile(resolve(checksPath)));
    await writeFile(source, sql);
    phase="non-superuser-candidate-capture";
    await runFixture({
      MIGRATION_CANDIDATE_NAME: migrationName,
      MIGRATION_CANDIDATE_SQL: source,
      MIGRATION_CANDIDATE_CAPTURE: capture,
      MIGRATION_CANDIDATE_MODULE: new URL("./capture-candidate.js", import.meta.url).href,
    });
    const { before, after, digest } = JSON.parse(await readFile(capture, "utf8"));
    phase="reviewed-artifact-generation";
    file = await createMigration(config, migrationName, sql);
    await writeFile(file + ".review.json", JSON.stringify({
      sqlChecksum: checksumText(sql), before, after, review: { digest, reason: reason.trim() },
    }, null, 2) + "\n", { flag: "wx" });
    sidecarWritten = true;
    await loadMigrationConfig(configPath);
    phase="non-superuser-upgrade-and-assertions";
    await runFixture({
      MIGRATION_LOCAL_UPGRADE: "1",
      MIGRATION_PREPARE_CHECKS: checks,
      MIGRATION_CANDIDATE_MODULE: new URL("./capture-candidate.js", import.meta.url).href,
    });
    console.log(file);
  } catch (error) {
    console.error(JSON.stringify(explainPrepareFailure(error,phase),null,2));
    if (file) await rm(file, { force: true });
    if (sidecarWritten) await rm(file + ".review.json", { force: true });
    throw error;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
