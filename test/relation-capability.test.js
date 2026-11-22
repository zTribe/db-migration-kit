import test from "node:test";
import assert from "node:assert/strict";
import { preflightRelationCapabilities } from "../src/relation-capability.js";

function client({owner="runtime_owner",canAlter=false,canSet=false,create=true,exists=true,canCreatePolicy=false}={}) {
  const calls=[];
  return {calls,async query(sql,args=[]) {
    calls.push([sql,args]);
    if(sql.startsWith("SAVEPOINT ")||sql.startsWith("ROLLBACK TO SAVEPOINT ")||
       sql.startsWith("RELEASE SAVEPOINT "))return {rows:[]};
    if(sql.startsWith("CREATE POLICY migration_kit_capability_probe ON ")) {
      if(!canCreatePolicy)throw Object.assign(new Error("must be owner of relation"),{code:"42501"});
      return {rows:[]};
    }
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

test("generic transactional CREATE POLICY probe proves live capability and rolls back",async()=>{
  const db=client({owner:"provider_owner",canCreatePolicy:true});
  const sql='CREATE POLICY scoped ON "tenant"."events" FOR SELECT USING (false);';
  await assert.rejects(preflightRelationCapabilities(db,sql),/cannot POLICY tenant.events/);
  assert.equal(db.calls.filter(([q])=>q.startsWith("SAVEPOINT ")).length,0,
    "probe must be opt-in inside a managed transaction");
  assert.deepEqual(await preflightRelationCapabilities(db,sql,
    {transactionalPolicyProbe:true}),{checked:1,created:0});
  const probes=db.calls.map(([q])=>q).filter(q=>/SAVEPOINT|CREATE POLICY migration_kit_capability_probe/.test(q));
  assert.deepEqual(probes,[
    "SAVEPOINT migration_kit_policy_capability_probe",
    'CREATE POLICY migration_kit_capability_probe ON "tenant"."events" AS RESTRICTIVE FOR SELECT TO PUBLIC USING (false)',
    "ROLLBACK TO SAVEPOINT migration_kit_policy_capability_probe",
    "RELEASE SAVEPOINT migration_kit_policy_capability_probe",
  ]);
});

test("failed transactional policy probe rolls back and rejects migration",async()=>{
  const db=client({owner:"provider_owner"});
  await assert.rejects(preflightRelationCapabilities(db,
    "CREATE POLICY scoped ON tenant.events FOR INSERT WITH CHECK (true);",
    {transactionalPolicyProbe:true}),/transactional CREATE POLICY probe failed/);
  assert.deepEqual(db.calls.slice(-2).map(([q])=>q),[
    "ROLLBACK TO SAVEPOINT migration_kit_policy_capability_probe",
    "RELEASE SAVEPOINT migration_kit_policy_capability_probe",
  ]);
});

test("policy exception does not authorize ALTER/DROP, SET ROLE, or other DDL",async()=>{
  const policy="tenant.events", opts={transactionalPolicyProbe:true};
  for(const sql of [
    "ALTER POLICY scoped ON "+policy+" USING (true);",
    "DROP POLICY scoped ON "+policy+";",
    "ALTER TABLE "+policy+" DISABLE ROW LEVEL SECURITY;",
    "CREATE INDEX idx_events ON "+policy+"(id);",
    "SET LOCAL ROLE provider_owner; CREATE POLICY scoped ON "+policy+" USING (true); RESET ROLE;",
  ]) {
    const db=client({owner:"provider_owner",canCreatePolicy:true});
    await assert.rejects(preflightRelationCapabilities(db,sql,opts),/migration capability denied/);
    assert.equal(db.calls.some(([q])=>q.startsWith("SAVEPOINT ")),false,sql);
  }
  await assert.rejects(preflightRelationCapabilities(client({exists:false,canCreatePolicy:true}),
    "CREATE POLICY scoped ON tenant.missing USING (true);",opts),/object not found/);
  await assert.rejects(preflightRelationCapabilities(client({canCreatePolicy:true}),
    "CREATE POLICY scoped ON tenant.events; DROP TABLE tenant.events;",opts),
    /migration capability denied/);
});
