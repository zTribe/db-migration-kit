import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { applyMigrations } from "../src/index.js";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const url = process.env.PG_TEST_URL;
test("real PG17: bounded migration lock fails closed without ledger writes", { skip: !url }, async () => {
  const pool = new pg.Pool({connectionString:url,max:3});
  const client = await pool.connect();
  const dir = await mkdtemp(join(tmpdir(),"kit-lock-"));
  const schema="kit_lock_it";
  const lockName="kit-lock-integration-timeout";
  try {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await writeFile(join(dir,"001_create.sql"),`CREATE SCHEMA IF NOT EXISTS ${schema}; CREATE TABLE ${schema}.sample(id int);`);
    await client.query("SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended($1,0))",[lockName]);
    await assert.rejects(
      () => applyMigrations(pool,{directory:dir,files:["001_create.sql"],schema,lockName,lockWaitMs:75,lockPollMs:10}),
      /advisory lock timeout/,
    );
    assert.equal((await pool.query("SELECT to_regclass($1) IS NULL AS absent",[`${schema}.schema_migrations`])).rows[0].absent,true);
    await client.query("SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended($1,0))",[lockName]);
    const applied=await applyMigrations(pool,{directory:dir,files:["001_create.sql"],schema,lockName});
    assert.deepEqual(applied.applied,["001_create"]);
  }finally{
    await client.query("SELECT pg_catalog.pg_advisory_unlock_all()").catch(()=>undefined);
    client.release();
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(()=>undefined);
    await rm(dir,{recursive:true,force:true});
    await pool.end();
  }
});
