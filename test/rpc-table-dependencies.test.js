import test from "node:test";
import assert from "node:assert/strict";
import {auditRpcTableDependencies} from "../src/rpc-table-dependencies.js";
const fn=(name,body)=>({schema_name:"api",name,definition:"CREATE FUNCTION api."+name+"() RETURNS integer LANGUAGE sql AS $function$\n"+body+"\n$function$;"});
const audit=(functions,tables,id="api.candles")=>auditRpcTableDependencies({functions},[{id,tables}]);
test("detects missing JOIN and returns explicit diff",()=>{
  const result=audit([fn("candles","SELECT 1 FROM chain.candles c JOIN chain.tokens t ON c.id=t.id")],["chain.candles"]);
  assert.deepEqual(result.results[0].missing,["chain.tokens"]);
  assert.equal(result.requiresReview,true);
  assert.equal(result.releaseApproved,false);
});
test("both tables declared is no lexical mismatch but never release approved",()=>{
  const result=audit([fn("candles","SELECT 1 FROM chain.candles c JOIN chain.tokens t ON c.id=t.id")],["chain.tokens","chain.candles"]);
  assert.deepEqual(result.results[0].actualTables,["chain.candles","chain.tokens"]);
  assert.equal(result.requiresReview,false);
  assert.equal(result.dependencyGraphComplete,false);
});
test("stale relation is review-required",()=>{
  const result=audit([fn("candles","SELECT 1 FROM chain.candles")],["chain.candles","chain.tokens"]);
  assert.deepEqual(result.results[0].stale,["chain.tokens"]);
  assert.equal(result.requiresReview,true);
});
test("INSERT UPDATE DELETE all register table references",()=>{
  const result=audit([fn("candles", "INSERT INTO app.buckets(id) VALUES (1); UPDATE app.buckets SET id=2; DELETE FROM app.buckets WHERE id=2")],["app.buckets"]);
  assert.deepEqual(result.results[0].actualTables,["app.buckets"]);
  assert.deepEqual(result.results[0].warnings,[]);
});
test("unqualified reference does not silently pass",()=>{
  assert.match(audit([fn("candles","SELECT * FROM buckets")],[]).results[0].warnings.join(","),/unqualified-relation/);
});
test("dynamic EXECUTE rejects automatic pass",()=>{
  assert.match(audit([fn("candles","EXECUTE 'SELECT 1 FROM chain.tokens'")],[]).results[0].warnings.join(","),/dynamic-sql/);
});
test("unknown function call rejects automatic pass",()=>{
  assert.match(audit([fn("candles","SELECT api.unknown()")],[]).results[0].warnings.join(","),/unresolved/);
});
test("direct helper function chain discovers nested dependency",()=>{
  const result=audit([fn("candles","SELECT api.helper()"),fn("helper","SELECT 1 FROM chain.tokens")],["chain.tokens"]);
  assert.deepEqual(result.results[0].actualTables,["chain.tokens"]);
  assert.equal(result.requiresReview,false);
});
test("recursive calls do not loop",()=>{
  const result=audit([fn("candles","SELECT api.candles()")],[]);
  assert.match(result.results[0].warnings.join(","),/recursive/);
});
test("overloaded functions require review",()=>{
  const result=audit([fn("candles","SELECT 1"),fn("candles","SELECT 2")],[]);
  assert.equal(result.requiresReview,true);
});
test("unsupported bodies do not pass",()=>{
  const result=audit([{schema_name:"api",name:"candles",definition:"LANGUAGE SQL RETURN 1"}],[]);
  assert.match(result.results[0].warnings.join(","),/unsupported/);
});
test("missing RPC and duplicate declarations reject",()=>{
  assert.equal(audit([],[]).requiresReview,true);
  assert.throws(()=>auditRpcTableDependencies({functions:[fn("candles","SELECT 1")]},[{id:"api.candles",tables:[]},{id:"api.candles",tables:[]}]));
  assert.throws(()=>auditRpcTableDependencies({functions:[fn("candles","SELECT 1")]},[{id:"api.candles",tables:["chain.tokens","chain.tokens"]}]));
});
test("comments and string literals do not invent references",()=>{
 const result=audit([fn("candles","-- FROM chain.fake\nSELECT 'JOIN chain.fake' AS text, 1 FROM chain.tokens")],["chain.tokens"]);
 assert.deepEqual(result.results[0].actualTables,["chain.tokens"]);
});

test("PLpgSQL UPSERT, RETURNING INTO and local variables do not fabricate table edges",()=>{
 const body = [
   "INSERT INTO app.api_rate_limit_buckets AS current_bucket (bucket_key, window_start, hit_count)",
   "VALUES ('k', now(), 1)",
   "ON CONFLICT (bucket_key, window_start) DO UPDATE SET hit_count = current_bucket.hit_count + 1",
   "RETURNING hit_count INTO v_hits;",
   "SELECT clock_timestamp() INTO v_now;",
   "DELETE FROM app.api_rate_limit_buckets WHERE bucket_key = 'k';",
 ].join("\\n");
 const result=audit([fn("candles",body)],["app.api_rate_limit_buckets"]);
 assert.deepEqual(result.results[0].actualTables,["app.api_rate_limit_buckets"]);
 assert.deepEqual(result.results[0].warnings,[]);
});

test("EXTRACT(epoch FROM v_now) is not a relation",()=>{
 const body = "SELECT extract(epoch FROM v_now) INTO v_seconds; DELETE FROM app.api_rate_limit_buckets WHERE bucket_key = 'k';";
 const report=audit([fn("candles",body)],["app.api_rate_limit_buckets"]);
 assert.deepEqual(report.results[0].warnings,[]);
 assert.deepEqual(report.results[0].actualTables,["app.api_rate_limit_buckets"]);
});
