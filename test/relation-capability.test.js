import test from "node:test";
import assert from "node:assert/strict";
import { preflightRelationCapabilities } from "../src/relation-capability.js";

function client({owner="runtime_owner",canAlter=false,canSet=false,create=true,exists=true}={}) {
  const calls=[];
  return {calls,async query(sql,args=[]) {
    calls.push([sql,args]);
    if(sql.includes("current_user AS role"))return {rows:[{role:"migration_user"}]};
    if(sql.includes("has_schema_privilege"))return {rows:[{can_create:create}]};
    if(sql.includes("pg_catalog.to_regclass"))return {rows:exists?[{owner,can_alter:canAlter,can_set:canSet}]:[]};
    if(sql.includes("pg_catalog.pg_has_role"))return {rows:[{can_set:canSet}]};
    throw Error("unexpected catalog query: "+sql);
  }};
}
test("ALTER TABLE rejects wrong owner before executing SQL",async()=>{
  const db=client();
  await assert.rejects(preflightRelationCapabilities(db,"ALTER TABLE app.messages ADD COLUMN extra integer;"),/cannot ALTER TABLE app.messages/);
  assert.equal(db.calls.filter(([sql])=>sql.includes("pg_catalog.to_regclass")).length,1);
});
test("trigger/policy/index preflights inspect actual table ownership",async()=>{
  for(const sql of [
    "CREATE TRIGGER wake AFTER INSERT ON app.messages FOR EACH ROW EXECUTE FUNCTION app.wake();",
    "ALTER POLICY private_rows ON app.messages USING (true);",
    "CREATE INDEX new_idx ON app.messages(id);"
  ]) await assert.rejects(preflightRelationCapabilities(client(),sql),/owner is runtime_owner/);
});
test("authorized owner and temporary SET ROLE are recognized from live catalog",async()=>{
  await preflightRelationCapabilities(client({canAlter:true}),"ALTER TABLE app.messages ADD COLUMN extra integer;");
  await preflightRelationCapabilities(client({canSet:true}),"SET LOCAL ROLE runtime_owner; ALTER TABLE app.messages ADD COLUMN extra integer; RESET ROLE;");
});
test("CREATE TABLE requires schema privilege; new relation may be changed in same transaction",async()=>{
  await assert.rejects(preflightRelationCapabilities(client({create:false}),"CREATE TABLE app.new_table (id integer);"),/no CREATE/);
  await preflightRelationCapabilities(client({exists:false}),"CREATE TABLE app.new_table (id integer); ALTER TABLE app.new_table ADD COLUMN name text;");
});
test("unqualified/quoted object names, missing objects and misleading literals fail closed",async()=>{
  await assert.rejects(preflightRelationCapabilities(client(),"ALTER TABLE messages ADD COLUMN bad integer;"),/schema-qualified/);
  await preflightRelationCapabilities(client({canAlter:true}), 'ALTER TABLE "app"."messages" ADD COLUMN good integer;');
  await assert.rejects(preflightRelationCapabilities(client(), 'ALTER TABLE "App"."messages" ADD COLUMN bad integer;'),/schema-qualified/);
  await assert.rejects(preflightRelationCapabilities(client(), 'ALTER TABLE "app"."Messages" ADD COLUMN bad integer;'),/schema-qualified/);
  await assert.rejects(preflightRelationCapabilities(client(), 'ALTER TABLE "app"."messages extra" ADD COLUMN bad integer;'),/schema-qualified/);
  await assert.rejects(preflightRelationCapabilities(client(), 'ALTER TABLE "app"."mes""sages" ADD COLUMN bad integer;'),/schema-qualified/);
  await assert.rejects(preflightRelationCapabilities(client({exists:false}),"ALTER TABLE app.missing ADD COLUMN bad integer;"),/object not found/);
  assert.deepEqual(await preflightRelationCapabilities(client(),"SELECT 'ALTER TABLE app.messages;'; -- CREATE TRIGGER x ON app.messages"),{checked:0,created:0});
});

test("PG17 generator's quoted relations resolve to the same live-catalog owner checks",async()=>{
  const db=client({owner:"chat_api_runtime_owner"});
  await assert.rejects(
    preflightRelationCapabilities(db, 'ALTER TABLE "app"."messages" ADD COLUMN "kit_test_note" text;'),
    /cannot ALTER TABLE app.messages; owner is chat_api_runtime_owner/
  );
  assert.equal(db.calls.filter(([sql])=>sql.includes("pg_catalog.to_regclass"))[0][1][0],"app.messages");
  await preflightRelationCapabilities(client({canAlter:true}), 'ALTER TABLE "app"."messages" ADD COLUMN "kit_test_note" text;');
  await preflightRelationCapabilities(client({exists:false}), 'CREATE TABLE "app"."new_table" (id integer); ALTER TABLE "app"."new_table" ADD COLUMN "name" text;');
  await assert.rejects(preflightRelationCapabilities(client({create:false}), 'CREATE TABLE "app"."new_table" (id integer);'),/no CREATE/);
});
