import test from "node:test";
import assert from "node:assert/strict";
import { compareRpcCatalogContracts } from "../src/rpc-contract-audit.js";
const id="api.token_candles(text,text)";
const fn=(result="TABLE(bucket_start timestamp with time zone, open text)",definition="select 1",security_definer=false)=>({
  schema_name:"api",name:"token_candles",args:"text,text",result,definition,security_definer,settings:null
});
const cat=(...functions)=>({functions});
test("same signature is advisory, never release-approved",()=>{
  const r=compareRpcCatalogContracts(cat(fn()),cat(fn()),[id]);
  assert.equal(r.requiresReview,false);
  assert.equal(r.releaseApproved,false);
  assert.equal(r.dependencyGraphComplete,false);
});
test("added field is only signature compatible",()=>{
  const r=compareRpcCatalogContracts(cat(fn()),cat(fn("TABLE(bucket_start timestamp with time zone, open text, volume text)")),[id]);
  assert.equal(r.changes[0].reason,"additive-fields");
  assert.equal(r.releaseApproved,false);
});
test("removed or retyped field requires review",()=>{
  assert.equal(compareRpcCatalogContracts(cat(fn()),cat(fn("TABLE(bucket_start timestamp with time zone)")),[id]).requiresReview,true);
  assert.equal(compareRpcCatalogContracts(cat(fn()),cat(fn("TABLE(bucket_start timestamp with time zone, open numeric)")),[id]).requiresReview,true);
});
test("changed implementation requires review even when result is unchanged",()=>{
  assert.equal(compareRpcCatalogContracts(cat(fn()),cat(fn(undefined,"select changed")),[id]).changes[0].reason,"implementation-changed");
});
test("security change requires review",()=>{
  assert.equal(compareRpcCatalogContracts(cat(fn()),cat(fn(undefined,undefined,true)),[id]).requiresReview,true);
});
test("missing before or after is never passed",()=>{
  assert.equal(compareRpcCatalogContracts(cat(fn()),cat(),[id]).requiresReview,true);
  assert.equal(compareRpcCatalogContracts(cat(),cat(fn()),[id]).requiresReview,true);
});
test("unsupported result shape demands review",()=>{
  assert.equal(compareRpcCatalogContracts(cat(fn()),cat(fn("SETOF custom_type")),[id]).changes[0].reason,"unsupported-output");
});
test("invalid inputs fail closed",()=>{
  assert.throws(()=>compareRpcCatalogContracts({},cat(fn()),[id]));
  assert.throws(()=>compareRpcCatalogContracts(cat(fn()),cat(fn()),[]));
  assert.throws(()=>compareRpcCatalogContracts(cat(fn()),cat(fn()),[id,id]));
});
