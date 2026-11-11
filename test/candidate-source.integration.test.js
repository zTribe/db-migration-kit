import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import {mkdtemp,writeFile,rm} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {applyMigrations,generateCandidateFromMigratedDatabase} from "../src/index.js";

const url=process.env.PG_TEST_URL;
test("real PG17: candidate extraction requires a complete audited SQL manifest", {skip:!url}, async()=>{
  const pool=new pg.Pool({connectionString:url});
  const dir=await mkdtemp(join(tmpdir(),"kit-candidate-source-"));
  const schema="kit_candidate_source_it";
  const file="001_schema.sql";
  const config={directory:dir,files:[file],schema,lockName:"kit-candidate-source-it"};
  const origin={repository:"zTribe/zTribe",ref:"a".repeat(40),schemas:[schema]};
  try {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await writeFile(join(dir,file),`CREATE SCHEMA ${schema}; CREATE TABLE ${schema}.messages(id integer);`);
    await assert.rejects(()=>generateCandidateFromMigratedDatabase(pool,config,origin),/does not match the complete migration manifest/);
    await applyMigrations(pool,config);
    const result=await generateCandidateFromMigratedDatabase(pool,config,origin);
    assert.equal(result.status,"candidate_needs_review");
    assert.equal(result.ledgerAudit.complete,true);
    assert.equal(result.ledgerAudit.applied,1);
    assert.equal(result.provenance.migrationChecksums.length,1);
    assert.match(result.provenance.migrationChecksums[0].checksum,/^[a-f0-9]{64}$/);
    assert.ok(result.objectPolicies.some(x=>x.kind==="table"&&x.key===`${schema}.messages`));
    assert.ok(result.objectPolicies.every(x=>x.reviewStatus==="needs_review"));
    await writeFile(join(dir,file),`CREATE SCHEMA ${schema}; CREATE TABLE ${schema}.messages(id bigint);`);
    await assert.rejects(()=>generateCandidateFromMigratedDatabase(pool,config,origin),/audit failed/);
  }finally {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(()=>undefined);
    await rm(dir,{recursive:true,force:true});
    await pool.end();
  }
});
