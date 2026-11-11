import test from "node:test";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import { applyMigrations, auditMigrations, inspectMigrations, inspectRuntimeSecurity } from "../src/index.js";

const url = process.env.PG_TEST_URL;
test("real PostgreSQL: ordered apply, transaction rollback, checksum drift, read-only audit and concurrency", { skip: !url }, async () => {
  const pool = new pg.Pool({ connectionString: url, max: 6 });
  const schema = "migration_kit_it";
  const dir = await mkdtemp(join(tmpdir(), "db-kit-"));
  const files = ["001_first.sql", "002_second.sql"];
  const options = { directory: dir, files, schema, ledgerTable: "schema_migrations", lockName: "migration-kit-integration-test" };
  try {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, files[0]), `CREATE TABLE ${schema}.sample (id integer primary key); INSERT INTO ${schema}.sample VALUES (1);`);
    await writeFile(join(dir, files[1]), `ALTER TABLE ${schema}.sample ADD COLUMN label text NOT NULL DEFAULT 'ok';`);
    const before = await inspectMigrations(pool, options);
    assert.equal(before.ok, true);
    assert.equal(before.pending.length, 2);
    const [a, b] = await Promise.all([applyMigrations(pool, options), applyMigrations(pool, options)]);
    assert.equal(a.applied.length + b.applied.length, 2);
    const after = await inspectMigrations(pool, options);
    assert.equal(after.ok, true);
    assert.equal(after.applied.length, 2);
    assert.equal(after.pending.length, 0);
    assert.equal((await pool.query(`SELECT label FROM ${schema}.sample WHERE id=1`)).rows[0].label, "ok");
    const ledgerBeforeAudit = await pool.query(`SELECT version,checksum FROM ${schema}.schema_migrations ORDER BY version`);
    const audit = await auditMigrations(pool, options);
    assert.equal(audit.ok, true);
    const ledgerAfterAudit = await pool.query(`SELECT version,checksum FROM ${schema}.schema_migrations ORDER BY version`);
    assert.deepEqual(ledgerAfterAudit.rows, ledgerBeforeAudit.rows, "audit must not mutate the ledger");
    const cliConfig = { ...options, directory: dir };
    await writeFile(join(dir, "migration-kit.config.json"), JSON.stringify(cliConfig));
    for (const command of ["status", "audit"]) {
      const cli = spawnSync(process.execPath, [new URL("../bin/db-migrate-kit.js", import.meta.url).pathname, command], {
        cwd: dir, encoding: "utf8", env: { ...process.env, MIGRATION_DATABASE_URL: url },
      });
      assert.equal(cli.status, 0, `local CLI ${command} failed: ${cli.stdout} ${cli.stderr}`);
    }
    await writeFile(join(dir, files[0]), `CREATE TABLE ${schema}.sample (id bigint primary key); INSERT INTO ${schema}.sample VALUES (1);`);
    await assert.rejects(() => auditMigrations(pool, options), /audit failed/);
    await assert.rejects(() => applyMigrations(pool, options), /checksum\/name mismatch/);
    const ledger = await pool.query(`SELECT count(*)::int AS count FROM ${schema}.schema_migrations`);
    assert.equal(ledger.rows[0].count, 2);

    // Restore the original migration before testing transactional rollback.
    // Otherwise checksum drift short-circuits apply and never executes the failing SQL.
    await writeFile(join(dir, files[0]), `CREATE TABLE ${schema}.sample (id integer primary key); INSERT INTO ${schema}.sample VALUES (1);`);
    const failingFile = "003_failing.sql";
    await writeFile(join(dir, failingFile), `CREATE TABLE ${schema}.must_rollback(id integer); SELECT * FROM ${schema}.table_that_does_not_exist;`);
    const failureOptions = { ...options, files: [...files, failingFile] };
    await assert.rejects(() => applyMigrations(pool, failureOptions));
    const rollbackState = await pool.query(`
      SELECT pg_catalog.to_regclass($1) IS NULL AS table_absent,
        NOT EXISTS (SELECT 1 FROM ${schema}.schema_migrations WHERE version=$2) AS ledger_absent
    `, [`${schema}.must_rollback`, "003_failing"]);
    assert.deepEqual(rollbackState.rows[0], { table_absent: true, ledger_absent: true });
  } finally {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(() => undefined);
    await rm(dir, { recursive: true, force: true });
    await pool.end();
  }
});

test("real PostgreSQL catalog: RLS, SECURITY DEFINER owner, search_path and effective grants", { skip: !url }, async () => {
  const pool = new pg.Pool({ connectionString: url, max: 4 });
  const schema = "migration_kit_security_it";
  try {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await pool.query(`DROP ROLE IF EXISTS kit_runtime_owner`);
    await pool.query(`DROP ROLE IF EXISTS kit_anon`);
    await pool.query("CREATE ROLE kit_runtime_owner NOLOGIN NOSUPERUSER NOBYPASSRLS");
    await pool.query("CREATE ROLE kit_anon NOLOGIN NOSUPERUSER NOBYPASSRLS");
    await pool.query(`CREATE SCHEMA ${schema}`);
    await pool.query(`CREATE TABLE ${schema}.private_rows(id integer primary key)`);
    await pool.query(`ALTER TABLE ${schema}.private_rows ENABLE ROW LEVEL SECURITY`);
    await pool.query(`CREATE FUNCTION ${schema}.safe_fn() RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS 'SELECT 1'`);
    await pool.query(`ALTER FUNCTION ${schema}.safe_fn() OWNER TO kit_runtime_owner`);
    await pool.query(`REVOKE ALL ON FUNCTION ${schema}.safe_fn() FROM PUBLIC`);
    await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO kit_anon`);
    await pool.query(`GRANT SELECT, INSERT ON ${schema}.private_rows TO kit_anon`);
    const report = await inspectRuntimeSecurity(pool, {
      schemas: [schema],
      requireRlsOn: [`${schema}.private_rows`],
      allowedDefinerOwners: ["kit_runtime_owner"],
      deniedExecuteRoles: ["kit_anon"],
      deniedTableDmlRoles: ["kit_anon"],
      deniedSchemaCreateRoles: ["kit_anon"],
    });
    assert.equal(report.ok, false);
    assert.ok(report.failures.some(x => x.includes("INSERT") || x.includes("SELECT"))); // DML privilege is caught from live catalogs.
    assert.ok(report.failures.some(x => x.includes("kit_anon has CREATE") ) === false);
    const selectDenied = await inspectRuntimeSecurity(pool, {
      schemas: [schema],
      requireRlsOn: [`${schema}.private_rows`],
      allowedDefinerOwners: ["kit_runtime_owner"],
      deniedExecuteRoles: ["kit_anon"],
      deniedTableSelectRoles: ["kit_anon"],
      deniedSchemaUsageRoles: ["kit_anon"],
      deniedSchemaCreateRoles: ["kit_anon"],
    });
    assert.ok(selectDenied.failures.some(x => x.includes("kit_anon has effective SELECT")));
    assert.ok(selectDenied.failures.some(x => x.includes("kit_anon has USAGE")));
    await pool.query(`REVOKE SELECT, INSERT ON ${schema}.private_rows FROM kit_anon`);
    await pool.query(`REVOKE USAGE ON SCHEMA ${schema} FROM kit_anon`);
    const clean = await inspectRuntimeSecurity(pool, {
      schemas: [schema],
      requireRlsOn: [`${schema}.private_rows`],
      allowedDefinerOwners: ["kit_runtime_owner"],
      deniedExecuteRoles: ["kit_anon"],
      deniedTableSelectRoles: ["kit_anon"],
      deniedTableDmlRoles: ["kit_anon"],
      deniedSchemaUsageRoles: ["kit_anon"],
      deniedSchemaCreateRoles: ["kit_anon"],
    });
    assert.deepEqual(clean.failures, [], `unexpected live catalog failures: ${clean.failures.join("; ")}`);
    await pool.query(`GRANT SELECT ON ${schema}.private_rows TO kit_anon`);
    const required = await inspectRuntimeSecurity(pool, {
      schemas: [schema],
      requireRlsOn: [`${schema}.private_rows`],
      allowedDefinerOwners: ["kit_runtime_owner"],
      allowedTablePrivileges: { kit_anon: ["SELECT"] },
      allowedSchemaPrivileges: { kit_anon: ["USAGE"] },
    });
    assert.ok(required.failures.some(x => x.includes("kit_anon lacks USAGE")));
    await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO kit_anon`);
    const requiredOk = await inspectRuntimeSecurity(pool, {
      schemas: [schema],
      requireRlsOn: [`${schema}.private_rows`],
      allowedDefinerOwners: ["kit_runtime_owner"],
      allowedTablePrivileges: { kit_anon: ["SELECT"] },
      allowedSchemaPrivileges: { kit_anon: ["USAGE"] },
    });
    assert.deepEqual(requiredOk.failures, []);
    const inventory = await inspectRuntimeSecurity(pool, {
      schemas: [schema],
      requiredTables: [`${schema}.private_rows`, `${schema}.missing_table`],
      requiredFunctions: [`${schema}.safe_fn()`, `${schema}.missing_fn()`],
      expectedTableOwners: { [`${schema}.private_rows`]: "kit_runtime_owner" },
      expectedFunctionOwners: { [`${schema}.safe_fn()`]: "kit_anon" },
      requiredRoles: ["kit_anon", "kit_role_missing_it"],
      forbidBypassRlsRoles: ["kit_anon"],
      forbidSuperuserRoles: ["kit_anon"],
      allowedDefinerOwners: ["kit_runtime_owner"],
    });
    assert.ok(inventory.failures.some(x => x.includes("missing_table") && x.includes("missing")));
    assert.ok(inventory.failures.some(x => x.includes("missing_fn") && x.includes("missing")));
    assert.ok(inventory.failures.some(x => x.includes("kit_role_missing_it") && x.includes("missing")));
    assert.ok(inventory.failures.some(x => x.includes("private_rows: expected owner")));
    assert.ok(inventory.failures.some(x => x.includes("safe_fn(): expected owner")));
    const validInventory = await inspectRuntimeSecurity(pool, {
      schemas: [schema],
      requiredTables: [`${schema}.private_rows`],
      requiredFunctions: [`${schema}.safe_fn()`],
      expectedFunctionOwners: { [`${schema}.safe_fn()`]: "kit_runtime_owner" },
      requiredRoles: ["kit_anon"],
      forbidBypassRlsRoles: ["kit_anon"],
      forbidSuperuserRoles: ["kit_anon"],
      allowedDefinerOwners: ["kit_runtime_owner"],
    });
    assert.deepEqual(validInventory.failures, []);


  } finally {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(() => undefined);
    await pool.query("DROP ROLE IF EXISTS kit_anon").catch(() => undefined);
    await pool.query("DROP ROLE IF EXISTS kit_runtime_owner").catch(() => undefined);
    await pool.end();
  }
});
