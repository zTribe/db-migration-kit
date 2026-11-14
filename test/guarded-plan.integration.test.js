import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import pg from "pg";
import { applyMigrations, guardMigration, loadMigrationConfig, planMigration, readTargetState } from "../src/index.js";

test("config → generated migration → rollback on unauthorized privilege → verified commit", {
  skip: !process.env.PG_TEST_URL,
}, async () => {
  const pool = new pg.Pool({ connectionString: process.env.PG_TEST_URL });
  const dir = await mkdtemp(join(tmpdir(), "kit-guard-"));
  const schema = "kit_guard_plan_test";
  const writeJson = (name, value) => writeFile(join(dir, name), JSON.stringify(value));
  const capture = async () => {
    const client = await pool.connect();
    try { return await readTargetState(client, [schema]); }
    finally { client.release(); }
  };
  try {
    await writeFile(join(dir, "001_initial.sql"), `CREATE TABLE ${schema}.messages (id integer);`);
    const config = { directory: ".", discovery: "counter", schema, lockName: schema, targetState: "target.json", review: "review.json" };
    const path = join(dir, "config.json");
    await writeJson("config.json", config);
    await applyMigrations(pool, await loadMigrationConfig(path));
    const before = await capture();
    const target = structuredClone(before);
    target.schema.columns.push({ schema_name: schema, table_name: "messages", name: "body",
      type: "text", not_null: false, default_expr: null, identity: "", generated: "" });
    const { digest } = planMigration(before, target);
    await writeJson("before.json", before);
    await writeJson("target.json", target);
    await writeJson("review.json", { digest, reason: "Add nullable message body" });
    const cli = new URL("../bin/db-migrate-kit.js", import.meta.url);
    const { fileURLToPath } = await import("node:url");
    await promisify(execFile)(process.execPath, [fileURLToPath(cli), "generate", "--config=config.json",
      "--from=before.json", "--name=message_body"], { cwd: dir });
    const migration = join(dir, "002_message_body.sql");
    const sql = await readFile(migration, "utf8");
    await writeJson("config.json", { ...config, guard: { version: "002_message_body", before: "before.json" } });
    await writeFile(migration, sql + `GRANT SELECT ON ${schema}.messages TO PUBLIC;\n`);
    const guarded = await loadMigrationConfig(path);
    await assert.rejects(applyMigrations(pool, guarded), /SQL differs/);
    await assert.rejects(applyMigrations(pool, {
      ...guarded, migrationGuard: guardMigration("002_message_body", before, target, { digest, reason: "Test rollback" }),
    }), /result differs/);
    assert.deepEqual(planMigration(await capture(), before).changes, []);
    assert.deepEqual(planMigration(await capture(), before).structure, []);
    await writeFile(migration, sql + "/* nested /* comment */ */ COMMIT;\n");
    await assert.rejects(applyMigrations(pool, {
      ...guarded, migrationGuard: guardMigration("002_message_body", before, target, { digest, reason: "Test transaction control" }),
    }), /leave transaction control to Kit/);
    assert.deepEqual(planMigration(await capture(), before).structure, []);
    for (const unauthorized of [
      "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC;",
      "REVOKE TEMPORARY ON DATABASE " + '"' + new URL(process.env.PG_TEST_URL).pathname.slice(1).replaceAll('"', '""') + '" FROM PUBLIC;',
    ]) {
      await writeFile(migration, sql + unauthorized + "\n");
      await assert.rejects(applyMigrations(pool, {
        ...guarded, migrationGuard: guardMigration("002_message_body", before, target, { digest, reason: "Test ACL rollback" }),
      }), /result differs/);
      assert.deepEqual(planMigration(await capture(), before).changes, []);
    }
    await writeFile(migration, sql);
    assert.deepEqual((await applyMigrations(pool, await loadMigrationConfig(path))).applied, ["002_message_body"]);
    assert.deepEqual(planMigration(await capture(), target).structure, []);
  } finally {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await pool.end();
    await rm(dir, { recursive: true, force: true });
  }
});

test("review accepts an equivalent migration role under a different login name", {
  skip: !process.env.PG_TEST_URL,
}, async () => {
  const { normalizeMigrationRole } = await import("../src/index.js");
  const client = new pg.Client({ connectionString: process.env.PG_TEST_URL });
  await client.connect();
  try {
    await client.query(`BEGIN;
      CREATE ROLE kit_snapshot_login LOGIN;
      CREATE SCHEMA kit_role_probe AUTHORIZATION kit_snapshot_login;
      SET ROLE kit_snapshot_login;
      CREATE TABLE kit_role_probe.messages (id integer)`);
    const before = normalizeMigrationRole(await readTargetState(client, ["kit_role_probe"]), "kit_snapshot_login");
    await client.query("RESET ROLE; ALTER ROLE kit_snapshot_login RENAME TO kit_deploy_login; SET ROLE kit_deploy_login");
    const guard = guardMigration("role_portability", before, before);
    await guard.before(client);
    await client.query("GRANT SELECT ON kit_role_probe.messages TO PUBLIC");
    await assert.rejects(guard.after(client), /result differs/);
  } finally {
    try { await client.query("ROLLBACK"); }
    finally { await client.end(); }
  }
});
