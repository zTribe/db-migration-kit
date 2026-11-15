import test from "node:test";
import assert from "node:assert/strict";
import { auditRpcTableDependenciesAst as audit } from "../src/rpc-table-dependencies-ast.js";
const sql=(name,body)=>({schema_name:"api",name,definition:"CREATE FUNCTION api."+name+"() RETURNS integer LANGUAGE sql AS $body$"+body+"$body$"});
const pl=(name,body)=>({schema_name:"api",name,definition:"CREATE FUNCTION api."+name+"() RETURNS integer LANGUAGE plpgsql AS $body$DECLARE v_now integer; BEGIN "+body+" END; $body$"});
const run=(functions,tables,id="api.test_fn")=>audit({functions},[{id,tables}]);
test("AST: JOIN omissions and removal",async()=>{
 const fn=sql("test_fn","SELECT 1 FROM chain.candles c JOIN chain.tokens t ON c.id=t.id");
 const missing=await run([fn],["chain.candles"]);
 assert.deepEqual(missing.results[0].missing,["chain.tokens"]);
 const ok=await run([fn],["chain.candles","chain.tokens"]);
 assert.deepEqual(ok.results[0].missing,[]);
 assert.deepEqual(ok.results[0].warnings,[]);
 assert.equal(ok.releaseApproved,false);
 const stale=await run([sql("test_fn","SELECT 1 FROM chain.candles")],["chain.candles","chain.tokens"]);
 assert.deepEqual(stale.results[0].stale,["chain.tokens"]);
});
test("AST: EXTRACT(epoch FROM variable) never becomes a relation",async()=>{
 const r=await run([pl("test_fn","v_now := EXTRACT(EPOCH FROM clock_timestamp())::integer; RETURN v_now;")],[]);
 assert.equal(r.results[0].actualTables.includes("v_now"),false);
 assert.equal(r.releaseApproved,false);
});
test("AST: PLpgSQL UPSERT RETURNING INTO does not fabricate dependencies",async()=>{
 const fn=pl("test_fn","INSERT INTO app.buckets (id) VALUES (1) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id RETURNING id INTO v_now; RETURN v_now;");
 const r=await run([fn],["app.buckets"]);
 console.log("AST_DIAGNOSTIC",JSON.stringify(r.results[0]));
 assert.deepEqual(r.results[0].missing,[]);
 assert.equal(r.results[0].actualTables.includes("app.buckets"),true);
});
test("AST: dynamic SQL requires review",async()=>{
 const r=await run([pl("test_fn","EXECUTE 'SELECT 1 FROM chain.tokens'; RETURN 1;")],[]);
 assert.equal(r.requiresReview,true);
 assert.match(r.results[0].warnings.join(" "),/dynamic|unparsed/);
});
test("AST: nested schema-qualified SQL functions",async()=>{
 const r=await run([sql("test_fn","SELECT api.helper()"),sql("helper","SELECT 1 FROM chain.tokens")],["chain.tokens"]);
 assert.deepEqual(r.results[0].missing,[]);
 assert.deepEqual(r.results[0].actualTables,["chain.tokens"]);
});
test("AST: unqualified relations and unknown functions flag review",async()=>{
 const a=await run([sql("test_fn","SELECT 1 FROM tokens")],[]);
 assert.equal(a.requiresReview,true);
 const b=await run([sql("test_fn","SELECT api.unknown()")],[]);
 assert.equal(b.requiresReview,true);
});
test("AST: invalid input and overload fail closed",async()=>{
 await assert.rejects(()=>audit({functions:[]},[]));
 const r=await run([sql("test_fn","SELECT 1"),sql("test_fn","SELECT 2")],[]);
 assert.equal(r.requiresReview,true);
});
