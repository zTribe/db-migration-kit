import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { readSchemaCatalogOnClient, compareRpcCatalogContracts } from "../src/index.js";

test("PG17 real catalog Before/After detects RPC implementation change", {skip:!process.env.PG_TEST_URL}, async()=>{
  const client=new pg.Client({connectionString:process.env.PG_TEST_URL});
  await client.connect();
  let began=false;
  try{
    await client.query("BEGIN");began=true;
    await client.query("CREATE SCHEMA kit_rpc_contract_it");
    await client.query("CREATE FUNCTION kit_rpc_contract_it.demo(p_value integer) RETURNS TABLE(result integer) LANGUAGE SQL AS 'SELECT p_value + 1'");
    const before=await readSchemaCatalogOnClient(client,["kit_rpc_contract_it"]);
    const recorded=before.functions.find(x=>x.name==="demo");
    assert.ok(recorded,"real PostgreSQL function catalog must contain demo()");
    assert.match(recorded.args,/p_value integer/);
    const id=recorded.schema_name+"."+recorded.name+"("+recorded.args+")";
    assert.equal(compareRpcCatalogContracts(before,before,[id]).requiresReview,false);
    await client.query("CREATE OR REPLACE FUNCTION kit_rpc_contract_it.demo(p_value integer) RETURNS TABLE(result integer) LANGUAGE SQL AS 'SELECT p_value + 2'");
    const after=await readSchemaCatalogOnClient(client,["kit_rpc_contract_it"]);
    const report=compareRpcCatalogContracts(before,after,[id]);
    assert.equal(report.requiresReview,true);
    assert.equal(report.changes[0].reason,"implementation-changed");
    assert.equal(report.releaseApproved,false);
    assert.equal(report.dependencyGraphComplete,false);
    assert.equal(compareRpcCatalogContracts({functions:[]},after,[id]).requiresReview,true);
  } finally {
    if(began)await client.query("ROLLBACK").catch(()=>{});
    await client.end();
  }
});
