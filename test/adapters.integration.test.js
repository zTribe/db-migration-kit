import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import { applyMigrations, baselineMigrations, auditMigrations } from "../src/index.js";

const url = process.env.PG_TEST_URL;

test("real PG17: Chat-style catalog baseline and later migrations share one ledger", { skip: !url }, async () => {
  const pool = new pg.Pool({ connectionString: url });
  const dir = await mkdtemp(join(tmpdir(), "kit-chat-"));
  const schema = "kit_chat_adapter_it";
  const files = ["001_initial.sql", "002_followup.sql"];
  const config = { directory: dir, files, schema, lockName: "kit-chat-adapter-it" };
  try {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await writeFile(join(dir, files[0]), `CREATE SCHEMA IF NOT EXISTS ${schema}; CREATE TABLE ${schema}.messages(id int primary key);`);
    await writeFile(join(dir, files[1]), `ALTER TABLE ${schema}.messages ADD COLUMN body text;`);
    await pool.query(`CREATE SCHEMA ${schema}`);
    await pool.query(`CREATE TABLE ${schema}.messages(id int primary key)`);
    let checks = 0;
    await assert.rejects(() => baselineMigrations(pool, { ...config, baselineThrough: "001_initial", verifyBaseline: async () => false }), /does not match/);
    const baseline = await baselineMigrations(pool, {
      ...config,
      baselineThrough: "001_initial",
      verifyBaseline: async client => {
        checks++;
        const { rows } = await client.query("SELECT to_regclass($1) IS NOT NULL AS present", [`${schema}.messages`]);
        return rows[0].present === true;
      },
    });
    assert.equal(checks, 1);
    assert.deepEqual(baseline.recorded, ["001_initial"]);
    const r = await applyMigrations(pool, config);
    assert.deepEqual(r.applied, ["002_followup"]);
    assert.equal((await auditMigrations(pool, config)).ok, true);
    const ledger = await pool.query(`SELECT version,source FROM ${schema}.schema_migrations ORDER BY version`);
    assert.deepEqual(ledger.rows, [{version:"001_initial",source:"baseline"},{version:"002_followup",source:"migration"}]);
  } finally {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(() => undefined);
    await rm(dir,{recursive:true,force:true});
    await pool.end();
  }
});

test("real PG17: Indexer-style hooks, target guard and transactional rollback", { skip: !url }, async () => {
  const pool = new pg.Pool({ connectionString: url });
  const dir = await mkdtemp(join(tmpdir(), "kit-indexer-"));
  const schema = "kit_indexer_adapter_it";
  const files = ["001_base.sql", "002_sensitive.sql"];
  const config = { directory: dir, files, schema, lockName: "kit-indexer-adapter-it" };
  try {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await writeFile(join(dir, files[0]), `CREATE SCHEMA IF NOT EXISTS ${schema}; CREATE TABLE ${schema}.audit(id integer);`);
    await writeFile(join(dir, files[1]), `INSERT INTO ${schema}.audit(id) VALUES (42);`);
    let hooks = [];
    const guarded = {
      ...config,
      verifyTarget: async client => {
        hooks.push("target");
        const { rows } = await client.query("SELECT current_database() AS db");
        assert.equal(rows.length, 1);
      },
      beforeMigrations: async () => hooks.push("bootstrap"),
      beforeMigration: async (_client, migration) => {
        hooks.push(migration.version);
        if (migration.version === "002_sensitive") throw new Error("destructive migration not approved");
      },
    };
    await assert.rejects(() => applyMigrations(pool, {...guarded, verifyTarget: async () => {throw new Error("wrong database identity")}}), /wrong database identity/);
    const none = await pool.query("SELECT to_regnamespace($1) IS NULL AS absent", [schema]);
    assert.equal(none.rows[0].absent,true,"identity failure must not create schema or ledger");
    await assert.rejects(() => applyMigrations(pool, guarded), /destructive migration not approved/);
    assert.deepEqual(hooks, ["target","bootstrap","001_base","002_sensitive"]);
    const count = await pool.query(`SELECT count(*)::integer AS n FROM ${schema}.audit`);
    assert.equal(count.rows[0].n, 0);
    const completed = await applyMigrations(pool, {...guarded, beforeMigration: async (_client,m) => hooks.push("allowed:"+m.version)});
    assert.deepEqual(completed.applied, ["002_sensitive"]);
    assert.equal((await pool.query(`SELECT count(*)::integer AS n FROM ${schema}.audit`)).rows[0].n,1);
  } finally {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(() => undefined);
    await rm(dir,{recursive:true,force:true});
    await pool.end();
  }
});

test("real PG17: nontransactional index migration is explicit, hooked and ledger-atomic on success", { skip: !url }, async () => {
  const pool = new pg.Pool({ connectionString: url });
  const dir = await mkdtemp(join(tmpdir(), "kit-index-concurrently-"));
  const schema = "kit_index_concurrent_it";
  const files = ["001_table.sql", "002_index.sql"];
  const config = { directory: dir, files, schema, lockName: "kit-index-concurrent-it" };
  try {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await writeFile(join(dir, files[0]), `CREATE SCHEMA IF NOT EXISTS ${schema}; CREATE TABLE ${schema}.events(id integer primary key, seq integer);`);
    await writeFile(join(dir, files[1]), `-- migrate:non-transactional-index\nCREATE INDEX CONCURRENTLY IF NOT EXISTS events_seq_idx ON ${schema}.events(seq);`);
    await assert.rejects(() => applyMigrations(pool, config), /requires explicit allowNonTransactional/);
    const before = await pool.query(`SELECT to_regclass($1) IS NULL AS absent`, [`${schema}.events_seq_idx`]);
    assert.equal(before.rows[0].absent, true);
    const calls = [];
    const result = await applyMigrations(pool, {
      ...config,
      allowNonTransactional: true,
      beforeMigration: async (_client, migration) => calls.push(migration.version),
    });
    assert.deepEqual(result.applied, ["002_index"]);
    assert.deepEqual(calls, ["002_index"]);
    const idx = await pool.query(`SELECT i.indisvalid AS valid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname='events_seq_idx'`, [schema]);
    assert.equal(idx.rows[0]?.valid, true);
    assert.equal((await auditMigrations(pool, config)).ok, true);
  } finally {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(() => undefined);
    await rm(dir,{recursive:true,force:true});
    await pool.end();
  }
});
