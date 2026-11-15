import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import {readSchemaCatalogOnClient,auditRpcTableDependencies} from "../src/index.js";
test("PG17 live RPC body: missing JOIN dependency is rejected", {skip:!process.env.PG_TEST_URL}, async()=>{
 const client=new pg.Client({connectionString:process.env.PG_TEST_URL});
 await client.connect();
 let tx=false;
 try{
  await client.query("BEGIN");tx=true;
  await client.query("CREATE SCHEMA kit_rpc_dep_it; CREATE TABLE kit_rpc_dep_it.candles(id integer); CREATE TABLE kit_rpc_dep_it.tokens(id integer)");
  await client.query("CREATE FUNCTION kit_rpc_dep_it.read_candles() RETURNS integer LANGUAGE SQL AS 'SELECT 1 FROM kit_rpc_dep_it.candles c JOIN kit_rpc_dep_it.tokens t ON c.id=t.id LIMIT 1'");
  const before=await readSchemaCatalogOnClient(client,["kit_rpc_dep_it"]);
  const missing=auditRpcTableDependencies(before,[{id:"kit_rpc_dep_it.read_candles",tables:["kit_rpc_dep_it.candles"]}]);
  assert.equal(missing.requiresReview,true);
  assert.deepEqual(missing.results[0].missing,["kit_rpc_dep_it.tokens"]);
  const complete=auditRpcTableDependencies(before,[{id:"kit_rpc_dep_it.read_candles",tables:["kit_rpc_dep_it.tokens","kit_rpc_dep_it.candles"]}]);
  assert.deepEqual(complete.results[0].missing,[]);
  assert.equal(complete.releaseApproved,false);
  await client.query("CREATE OR REPLACE FUNCTION kit_rpc_dep_it.read_candles() RETURNS integer LANGUAGE SQL AS 'SELECT 1 FROM kit_rpc_dep_it.candles LIMIT 1'");
  const after=await readSchemaCatalogOnClient(client,["kit_rpc_dep_it"]);
  const stale=auditRpcTableDependencies(after,[{id:"kit_rpc_dep_it.read_candles",tables:["kit_rpc_dep_it.tokens","kit_rpc_dep_it.candles"]}]);
  assert.deepEqual(stale.results[0].stale,["kit_rpc_dep_it.tokens"]);
  assert.equal(stale.requiresReview,true);
 }finally{
  if(tx)await client.query("ROLLBACK").catch(()=>{});
  await client.end();
 }
});
