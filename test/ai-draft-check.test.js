import test from "node:test";
import assert from "node:assert/strict";
import { checkAiMigrationDraft } from "../src/ai-draft-check.js";
const policy={legacyThrough:"066_old",recipes:[]};
const analyzer=async()=>({touches:[],uncertain:false,warnings:[]});
const check=(name,sql,more={})=>checkAiMigrationDraft({name,sql,ownerConfig:policy,analyzer,...more});
test("AI draft check accepts simple candidate without granting release",async()=>{
 const r=await check("add_column","ALTER TABLE app.messages ADD COLUMN note text;");
 assert.equal(r.ok,true);assert.equal(r.releaseApproved,false);
 assert.match(r.sqlChecksum,/^[a-f0-9]{64}$/);assert.equal(r.issues.length,0);
});
test("AI draft check blocks unreviewed role, transaction and concurrent index",async()=>{
 for(const sql of ["SET LOCAL ROLE runtime_owner; SELECT 1;",
  "BEGIN; CREATE TABLE app.x(id int); COMMIT;",
  "CREATE INDEX CONCURRENTLY x_idx ON app.x(id);"]) {
  assert.equal((await check("candidate",sql)).ok,false,sql);
 }
});
test("AI draft check requires fixed SECURITY DEFINER search_path",async()=>{
 const sql="CREATE FUNCTION app.secure() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'select 1';";
 assert.ok((await check("secure",sql)).issues.some(i=>i.code==="DEFINER_PATH"));
});
test("comment and quoted text must not invent forbidden SQL",async()=>{
 const sql="SELECT 'SET LOCAL ROLE owner; CREATE INDEX CONCURRENTLY idx ON app.x(id)'; -- SECURITY DEFINER";
 assert.equal((await check("quoted",sql)).ok,true);
});
test("Owner recipe rejects missing explicit approval but accepts correct reviewed recipe",async()=>{
 const sql="GRANT CREATE ON SCHEMA api TO runtime_owner; SET LOCAL ROLE runtime_owner; "+
 "CREATE OR REPLACE FUNCTION api.v2() RETURNS int LANGUAGE sql AS 'select 1'; "+
 "RESET ROLE; REVOKE CREATE ON SCHEMA api FROM runtime_owner;";
 assert.equal((await check("v2",sql)).ok,false);
 const result=await check("v2",sql,{ownerConfig:{recipes:[
  {name:"v2",role:"runtime_owner",schema:"api",functionName:"v2",mode:"set-role"}
 ]}});
 assert.equal(result.ok,true);
});
test("PG18 parser uncertainty is review-only and never a release approval",async()=>{
 const result=await check("create_table","CREATE TABLE app.example(id int);",{
 analyzer:async()=>{throw Error("PG18 mismatch");}
 });
 assert.equal(result.ok,true);
 assert.ok(result.issues.some(i=>i.code==="AST_PARSE_UNCERTAIN"));
 assert.equal(result.releaseApproved,false);
});
test("bad names and missing Owner policy fail closed",async()=>{
 assert.equal((await check("Bad Name","SELECT 1;")).ok,false);
 assert.equal((await check("ok","SELECT 1;",{ownerConfig:null})).ok,false);
});

test("opaque DO block produces a mandatory manual-review finding",async()=>{
 const result=await check("runtime_check","DO $$ BEGIN EXECUTE 'ALTER TABLE app.messages DROP COLUMN id'; END $$;");
 assert.equal(result.ok,true);
 assert.ok(result.issues.some(x=>x.code==="DYNAMIC_SQL"&&x.severity==="review"));
});
