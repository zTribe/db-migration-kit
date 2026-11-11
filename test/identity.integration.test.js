import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { verifyDatabaseTarget, applyMigrations } from "../src/index.js";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const url = process.env.PG_TEST_URL;
test("real PostgreSQL 17: DB identity marker prevents a wrong-project or wrong-environment apply", { skip: !url }, async () => {
  const pool = new pg.Pool({connectionString:url});
  const schema = "kit_identity_it";
  const dir = await mkdtemp(join(tmpdir(),"kit-target-"));
  try {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await pool.query(`CREATE SCHEMA ${schema}`);
    await pool.query(`CREATE TABLE ${schema}.target_identity (singleton boolean primary key default true check (singleton), project_ref text not null, environment text not null)`);
    await pool.query(`INSERT INTO ${schema}.target_identity(singleton,project_ref,environment) VALUES (true,'test-project-123','dev')`);
    const base = {schema,table:"target_identity",projectRef:"test-project-123",environment:"dev"};
    assert.deepEqual(await verifyDatabaseTarget(pool,base), {verified:true,environment:"dev"});
    await assert.rejects(() => verifyDatabaseTarget(pool,{...base,projectRef:"production-project-999"}), /mismatch/);
    await assert.rejects(() => verifyDatabaseTarget(pool,{...base,environment:"production"}), /mismatch/);
    await assert.rejects(() => verifyDatabaseTarget(pool,{...base,table:"missing_table"}));
    await writeFile(join(dir,"001_create.sql"),`CREATE TABLE ${schema}.should_not_exist(id int);`);
    const config={directory:dir,files:["001_create.sql"],schema,lockName:"kit-identity-it"};
    await assert.rejects(() => applyMigrations(pool,{...config,verifyTarget:client=>verifyDatabaseTarget(client,{...base,projectRef:"wrong-project-456"})}),/mismatch/);
    const before=await pool.query("SELECT to_regclass($1) IS NULL AS absent",[`${schema}.should_not_exist`]);
    assert.equal(before.rows[0].absent,true);
    const ok=await applyMigrations(pool,{...config,verifyTarget:client=>verifyDatabaseTarget(client,base)});
    assert.deepEqual(ok.applied,["001_create"]);
  }finally{
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(()=>undefined);
    await rm(dir,{recursive:true,force:true});
    await pool.end();
  }
});
