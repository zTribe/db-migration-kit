import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import {
  collectSecurityCatalog, inspectRuntimeSecurity, generateCandidatePolicy,
  assertApprovedSecurityPolicy, inventorySecurityObjects,
} from "../src/index.js";

const url=process.env.PG_TEST_URL;
test("PG17: inheritance, column grants, sequence ACL, RLS policy and candidate fail-closed", {skip:!url}, async()=>{
  const pool=new pg.Pool({connectionString:url,max:4});
  const s="kit_object_matrix_it",parent="kit_matrix_parent_it",child="kit_matrix_child_it";
  try {
    await pool.query(`DROP SCHEMA IF EXISTS ${s} CASCADE`);
    await pool.query(`DROP ROLE IF EXISTS ${child}`);
    await pool.query(`DROP ROLE IF EXISTS ${parent}`);
    await pool.query(`CREATE ROLE ${parent} NOLOGIN NOSUPERUSER NOBYPASSRLS`);
    await pool.query(`CREATE ROLE ${child} NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS`);
    await pool.query(`GRANT ${parent} TO ${child} WITH INHERIT TRUE`);
    await pool.query(`CREATE SCHEMA ${s}`);
    await pool.query(`CREATE TABLE ${s}.messages(id integer, body text, secret text)`);
    await pool.query(`ALTER TABLE ${s}.messages ENABLE ROW LEVEL SECURITY`);
    await pool.query(`ALTER TABLE ${s}.messages FORCE ROW LEVEL SECURITY`);
    await pool.query(`CREATE POLICY readable ON ${s}.messages FOR SELECT TO PUBLIC USING (true)`);
    await pool.query(`CREATE SEQUENCE ${s}.message_seq`);
    await pool.query(`GRANT USAGE ON SCHEMA ${s} TO ${parent}`);
    await pool.query(`GRANT SELECT (body), UPDATE (body) ON ${s}.messages TO ${parent}`);
    await pool.query(`GRANT USAGE ON SEQUENCE ${s}.message_seq TO ${parent}`);
    const base={schemas:[s],objectPolicies:[
      {kind:"table",key:`${s}.messages`,rls:true,forceRls:true},
      {kind:"column",key:`${s}.messages.body`,privileges:{[child]:{SELECT:"allow",UPDATE:"allow"}}},
      {kind:"column",key:`${s}.messages.secret`,privileges:{[child]:{SELECT:"deny",UPDATE:"deny"}}},
      {kind:"sequence",key:`${s}.message_seq`,privileges:{[child]:{USAGE:"allow",UPDATE:"deny"}}},
      {kind:"role",key:child,memberOf:[parent],superuser:false,bypassRls:false},
      {kind:"policy",key:`${s}.messages.readable`,permissive:true,command:"r",roles:["PUBLIC"]},
    ]};
    const report=await inspectRuntimeSecurity(pool,base);
    assert.deepEqual(report.failures,[],report.failures.join("\n"));
    assert.equal(report.snapshot.memberships.some(m=>m.member===child&&m.parent===parent&&m.inherit_option),true);
    assert.ok(report.snapshot.inventory.objects.some(x=>x.kind==="policy"&&x.key===`${s}.messages.readable`));
    assert.ok(report.snapshot.inventory.objects.some(x=>x.kind==="column"&&x.key===`${s}.messages.secret`));
    const candidate=generateCandidatePolicy(report.snapshot,{provenance:{
      repository:"zTribe/zTribe",ref:"perf/chat-loading-and-sync",migrationFiles:["supabase/migrations/fixture.sql"],
    },roles:[child]});
    assert.equal(candidate.status,"candidate_needs_review");
    assert.ok(candidate.objectPolicies.every(x=>x.reviewStatus==="needs_review"));
    assert.ok(candidate.objectPolicies.some(x=>x.kind==="column"&&x.privileges?.[child]?.UPDATE==="allow"));
    assert.throws(()=>assertApprovedSecurityPolicy(candidate),/not approved/);
    await pool.query(`GRANT SELECT (secret) ON ${s}.messages TO ${parent}`);
    const denied=await inspectRuntimeSecurity(pool,base);
    assert.ok(denied.diagnostics.some(x=>x.objectKind==="column"&&x.objectKey===`${s}.messages.secret`&&x.role===child&&x.permission==="SELECT"&&x.code==="PRIVILEGE_MISMATCH"));
    await pool.query(`REVOKE USAGE ON SEQUENCE ${s}.message_seq FROM ${parent}`);
    const missing=await inspectRuntimeSecurity(pool,base);
    assert.ok(missing.diagnostics.some(x=>x.objectKind==="sequence"&&x.permission==="USAGE"&&x.code==="PRIVILEGE_MISMATCH"));
  } finally {
    await pool.query(`DROP SCHEMA IF EXISTS ${s} CASCADE`).catch(()=>undefined);
    await pool.query(`DROP ROLE IF EXISTS ${child}`).catch(()=>undefined);
    await pool.query(`DROP ROLE IF EXISTS ${parent}`).catch(()=>undefined);
    await pool.end();
  }
});
