import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import {readSchemaCatalogOnClient} from "../src/index.js";
import {auditRpcTableDependenciesAst} from "../src/rpc-table-dependencies-ast.js";
test("PG17 live SQL and PLpgSQL functions audited through AST", {skip:!process.env.PG_TEST_URL}, async()=>{
 const client=new pg.Client({connectionString:process.env.PG_TEST_URL});
 await client.connect();
 let active=false;
 try{
  await client.query("BEGIN");active=true;
  await client.query("CREATE SCHEMA kit_ast_pg17; CREATE TABLE kit_ast_pg17.tokens(id integer primary key); CREATE TABLE kit_ast_pg17.candles(id integer primary key)");
  await client.query("CREATE FUNCTION kit_ast_pg17.candle_count() RETURNS integer LANGUAGE sql AS 'SELECT count(*)::integer FROM kit_ast_pg17.candles c JOIN kit_ast_pg17.tokens t ON c.id=t.id'");
  await client.query("CREATE FUNCTION kit_ast_pg17.touch_tokens() RETURNS integer LANGUAGE plpgsql AS $$DECLARE v_now integer; BEGIN INSERT INTO kit_ast_pg17.tokens(id) VALUES(2) ON CONFLICT (id) DO UPDATE SET id=EXCLUDED.id RETURNING id INTO v_now; RETURN v_now; END;$$");
  const catalog=await readSchemaCatalogOnClient(client,["kit_ast_pg17"]);
  const report=await auditRpcTableDependenciesAst(catalog,[
   {id:"kit_ast_pg17.candle_count",tables:["kit_ast_pg17.candles"]},
   {id:"kit_ast_pg17.touch_tokens",tables:["kit_ast_pg17.tokens"]},
  ]);
  assert.deepEqual(report.results[0].missing,["kit_ast_pg17.tokens"]);
  assert.deepEqual(report.results[1].missing,[]);
  assert.deepEqual(report.results[1].actualTables,["kit_ast_pg17.tokens"]);
  assert.equal(report.requiresReview,true);
  assert.equal(report.releaseApproved,false);
  assert.equal(report.dependencyGraphComplete,false);
  assert.equal(report.parserMajor,18);
  assert.equal(report.targetPostgresMajor,17);
 }finally{
  if(active)await client.query("ROLLBACK").catch(()=>{});
  await client.end();
 }
});
