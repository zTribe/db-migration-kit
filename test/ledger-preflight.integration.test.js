import pg from "pg";
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checksumText, applyMigrations, baselineMigrations, inspectMigrations } from "../src/index.js";
import { assertLocalTestDatabase } from "../src/testing.js";

test("local integration connection guard rejects remote or non-PostgreSQL targets", () => {
  assert.throws(() => assertLocalTestDatabase("postgresql://postgres:secret@db.example.supabase.co:5432/postgres"), /loopback/);
  assert.throws(() => assertLocalTestDatabase("https://localhost/test"), /loopback/);
  assert.throws(() => assertLocalTestDatabase(""), /required/);
  assert.equal(assertLocalTestDatabase("postgresql://postgres:secret@127.0.0.1:55432/postgres").hostname, "127.0.0.1");
});

test("Kit rejects unknown ledger versions before executing new SQL", { skip: !process.env.PG_TEST_URL }, async () => {
  const url = process.env.PG_TEST_URL;
  const dir = await mkdtemp(join(tmpdir(), "kit-unknown-ledger-"));
  const schema = "kit_unknown_ledger_it";
  const files = ["001_first.sql", "002_second.sql"];
  try {
    await writeFile(join(dir, files[0]), "select 1;\n");
    await writeFile(join(dir, files[1]), `create table ${schema}.must_not_exist(id integer);\n`);
    assertLocalTestDatabase(url);
    const pool = new pg.Pool({ connectionString: url });
    try {
      try {
        await pool.query(`drop schema if exists ${schema} cascade`);
        await pool.query(`create schema ${schema}`);
        await pool.query(`create table ${schema}.schema_migrations(version text primary key,name text not null,checksum text not null,source text not null check(source in ('migration','baseline')), applied_at timestamptz not null default now())`);
        await pool.query(`insert into ${schema}.schema_migrations(version,name,checksum,source) values ($1,$2,$3,'migration')`, ["999_unknown", "999_unknown.sql", "legacy"]);
        const config = { directory: dir, files, schema, lockName: "kit-unknown-ledger-test" };
        const report = await inspectMigrations(pool, config);
        assert.deepEqual(report.unknown.map(x=>x.version), ["999_unknown"]);
        await assert.rejects(applyMigrations(pool, config), /unknown applied migration/);
        const state = await pool.query(`select count(*)::integer as n from ${schema}.schema_migrations`);
        assert.equal(state.rows[0].n, 1);
        assert.equal((await pool.query("select to_regclass($1) as x", [`${schema}.must_not_exist`])).rows[0].x, null);
      } finally { await pool.query(`drop schema if exists ${schema} cascade`); }
    } finally { await pool.end(); }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("Kit baseline only records the verified migration prefix", { skip: !process.env.PG_TEST_URL }, async () => {
  const url = process.env.PG_TEST_URL;
  const dir = await mkdtemp(join(tmpdir(), "kit-prefix-"));
  const schema = "kit_verified_prefix_it";
  const files = ["001_first.sql", "002_second.sql", "003_third.sql"];
  try {
    for (const file of files) await writeFile(join(dir,file),"select 1;\n");
    assertLocalTestDatabase(url);
    const pool = new pg.Pool({ connectionString: url });
    try {
      try {
        await pool.query(`drop schema if exists ${schema} cascade`);
        const config = { directory: dir, files, schema, lockName: "kit-verified-prefix-test", baselineThrough: "002_second", verifyBaseline: async () => true };
        await assert.rejects(baselineMigrations(pool, { ...config, baselineThrough: "999_unknown" }), /not in the migration manifest/);
        const result = await baselineMigrations(pool, config);
        assert.deepEqual(result.recorded, ["001_first","002_second"]);
        const records = await pool.query(`select version,source from ${schema}.schema_migrations order by version`);
        assert.deepEqual(records.rows, [{version:"001_first",source:"baseline"},{version:"002_second",source:"baseline"}]);
        const report = await inspectMigrations(pool, config);
        assert.deepEqual(report.pending.map(x=>x.version),["003_third"]);
      } finally { await pool.query(`drop schema if exists ${schema} cascade`); }
    } finally { await pool.end(); }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
