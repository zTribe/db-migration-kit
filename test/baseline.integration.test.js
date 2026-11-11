import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { checksumText, inspectMigrations, auditMigrations } from "../src/index.js";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const url=process.env.PG_TEST_URL;
test("real PG17: Chat baseline strict checksum and Indexer pinned legacy marker are both audited", {skip:!url}, async()=>{
  const pool=new pg.Pool({connectionString:url});
  const dir=await mkdtemp(join(tmpdir(),"kit-legacy-baseline-"));
  const schema="kit_legacy_baseline_it";
  const file="001_history.sql";
  const sql="SELECT 1;";
  const version="001_history";
  const marker="baseline-existing-schema";
  try{
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await pool.query(`CREATE SCHEMA ${schema}`);
    await pool.query(`CREATE TABLE ${schema}.schema_migrations(version text primary key,name text not null,checksum text not null,source text not null,applied_at timestamptz not null default now())`);
    await writeFile(join(dir,file),sql);
    const config={directory:dir,files:[file],schema};
    await pool.query(`INSERT INTO ${schema}.schema_migrations(version,name,checksum,source) VALUES($1,$2,$3,'baseline')`,[version,file,marker]);
    let check=await inspectMigrations(pool,config);
    assert.deepEqual(check.drift.map(x=>x.version),[version],"unapproved legacy sentinel must fail");
    const legacy={...config,legacyBaselineChecksums:{[version]:{ledgerChecksum:marker,sqlChecksum:checksumText(sql)}}};
    assert.equal((await auditMigrations(pool,legacy)).ok,true);
    await writeFile(join(dir,file),"SELECT 2;");
    check=await inspectMigrations(pool,legacy);
    assert.deepEqual(check.drift.map(x=>x.version),[version],"even allowlisted legacy baseline must detect edited SQL");
    await writeFile(join(dir,file),sql);
    await pool.query(`UPDATE ${schema}.schema_migrations SET checksum='wrong' WHERE version=$1`,[version]);
    check=await inspectMigrations(pool,legacy);
    assert.deepEqual(check.drift.map(x=>x.version),[version],"edited historical sentinel must fail");
    await pool.query(`UPDATE ${schema}.schema_migrations SET checksum=$1 WHERE version=$2`,[checksumText(sql),version]);
    assert.equal((await auditMigrations(pool,config)).ok,true,"Chat-style baseline must match SHA256 directly");
  }finally{
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(()=>undefined);
    await rm(dir,{recursive:true,force:true});
    await pool.end();
  }
});
