import test from "node:test";
import assert from "node:assert/strict";
import {createOwnerMaintenancePolicy,acquireTemporaryOwnerRole,releaseTemporaryOwnerRole} from "../src/owner-maintenance.js";

const chat=createOwnerMaintenancePolicy({legacyThrough:"20261120163709_old",recipes:[
 {name:"list_v1",role:"chat_api_runtime_owner",schema:"app",functionName:"list_v1",mode:"transfer"}
]});
const sql="GRANT CREATE ON SCHEMA app TO chat_api_runtime_owner; "+
"CREATE FUNCTION app.list_v1() RETURNS integer LANGUAGE sql AS 'select 1'; "+
"ALTER FUNCTION app.list_v1() OWNER TO chat_api_runtime_owner; "+
"REVOKE CREATE ON SCHEMA app FROM chat_api_runtime_owner;";

test("Chat versioned RPC requires explicit reviewed owner transfer",()=>{
 assert.equal(chat.forCandidate("list_v1",sql).role,"chat_api_runtime_owner");
 assert.equal(chat.forMigration({version:"20261121122000_list_v1",sql}).functionName,"list_v1");
 assert.equal(chat.forMigration({version:"20261121122000_normal",sql:"CREATE TABLE app.sample(id integer);"}),null);
 assert.throws(()=>chat.forCandidate("unknown",sql),/approved recipe/);
 assert.throws(()=>chat.forMigration({version:"20261121122000_other",sql:"ALTER FUNCTION app.rogue() OWNER TO chat_api_runtime_owner;"}),/approved recipe/);
 assert.throws(()=>chat.forCandidate("list_v1",sql+" ALTER FUNCTION app.other() OWNER TO chat_api_runtime_owner;"),/unexpected function DDL/);
 assert.throws(()=>chat.forCandidate("list_v1",sql.replace(/REVOKE CREATE[^;]+;/,"")),/requires temporary CREATE/);
 assert.throws(()=>chat.forCandidate("list_v1",sql+" GRANT chat_api_runtime_owner TO current_user;"),/forbids SQL role grants|forbids extra SQL statement/);
});
test("Indexer counter-based policy uses the same Kit engine",()=>{
 const indexer=createOwnerMaintenancePolicy({legacyThrough:"052_role_cleanup",recipes:[
  {name:"read_v2",role:"indexer_api_read",schema:"api",functionName:"read_v2",mode:"set-role"}
 ]});
 const body="GRANT CREATE ON SCHEMA api TO indexer_api_read; SET LOCAL ROLE indexer_api_read; "+
  "CREATE OR REPLACE FUNCTION api.read_v2() RETURNS integer LANGUAGE sql AS 'SELECT 1'; "+
  "RESET ROLE; REVOKE CREATE ON SCHEMA api FROM indexer_api_read;";
 assert.equal(indexer.forMigration({version:"053_read_v2",sql:body}).role,"indexer_api_read");
 assert.throws(()=>indexer.forCandidate("unknown",body),/approved recipe/);
 assert.throws(()=>indexer.forCandidate("read_v2",body.replace("RESET ROLE;","")),/RESET ROLE/);
});

test("Owner recipe enforces actual SQL order, single grants and quoted-literal immunity",()=>{
 const role="chat_api_runtime_owner";
 const baseSql="GRANT CREATE ON SCHEMA app TO "+role+"; SET LOCAL ROLE "+role+"; "+
   "CREATE OR REPLACE FUNCTION app.approved() RETURNS integer LANGUAGE sql AS 'select 1'; "+
   "RESET ROLE; REVOKE CREATE ON SCHEMA app FROM "+role+";";
 const policy=createOwnerMaintenancePolicy({recipes:[{
   name:"approved",role,schema:"app",functionName:"approved",mode:"set-role"
 }]});
 assert.equal(policy.forCandidate("approved",baseSql).mode,"set-role");
 const revoke="REVOKE CREATE ON SCHEMA app FROM "+role+";";
 const wrongOrder=baseSql.replace("RESET ROLE; "+revoke,revoke+" RESET ROLE;");
 assert.throws(()=>policy.forCandidate("approved",wrongOrder),/enclose only/);
 assert.throws(()=>policy.forCandidate("approved",revoke+" "+baseSql),/one ordered/);
 assert.throws(()=>policy.forCandidate("approved",baseSql.replace(
   "CREATE OR REPLACE FUNCTION","CREATE TABLE app.rogue(id int); CREATE OR REPLACE FUNCTION"
 )),/unrelated object DDL/);
 assert.throws(()=>policy.forCandidate("approved",baseSql.replace(
   "SET LOCAL ROLE "+role+";","SET LOCAL ROLE untrusted; SET LOCAL ROLE "+role+";"
 )),/exactly one|forbids extra SQL statement/);
 assert.throws(()=>policy.forCandidate("approved",baseSql+" SELECT 'GRANT other TO current_user; ALTER TABLE app.rogue';"),/forbids extra SQL statement/);
 assert.equal(policy.forCandidate("approved",baseSql+" -- SET ROLE attacker; GRANT attacker TO current_user;").mode,"set-role");
});

test("Owner transfer demands ordered CREATE, ALTER OWNER and REVOKE",()=>{
 const misplaced=sql.replace(
   "ALTER FUNCTION app.list_v1() OWNER TO chat_api_runtime_owner;",
   "REVOKE CREATE ON SCHEMA app FROM chat_api_runtime_owner; ALTER FUNCTION app.list_v1() OWNER TO chat_api_runtime_owner;"
 ).replace(/REVOKE CREATE ON SCHEMA app FROM chat_api_runtime_owner;$/, "");
 assert.throws(()=>chat.forCandidate("list_v1",misplaced),/transfer before CREATE revoke/);
});

function fake({admin=false,canSet=false,inherited=false,bypassRls=false}={}) {
 const queries=[];let roleSet=canSet;
 return {queries,async query(sql,args=[]) {
  queries.push([sql,args]);
  if(sql.includes("session_user AS login"))return{rows:[{role:"migrator",login:"migrator",rolsuper:false,rolbypassrls:bypassRls,inherited,can_set:roleSet,admin_option:admin,self_grant:false}]};
  if(sql.startsWith("GRANT ")){roleSet=true;return{rows:[]}};
  if(sql.startsWith("REVOKE ")){roleSet=false;return{rows:[]}};
  if(sql==="SELECT current_user AS login")return{rows:[{login:"migrator"}]};
  if(sql.includes("schema_create"))return{rows:[{can_set:roleSet,inherited:false,schema_create:false}]};
  if(sql.includes("can_set"))return{rows:[{can_set:roleSet,inherited:false}]};
  throw Error(sql);
 }};
}
test("role capability is temporary and refuses unapproved login",async()=>{
 const db=fake({admin:true}),lease=await acquireTemporaryOwnerRole(db,{role:"chat_api_runtime_owner",schema:"app"});
 assert.equal(lease.added,true);
 await releaseTemporaryOwnerRole(db,lease);
 assert.equal(db.queries.filter(q=>q[0].startsWith("GRANT")).length,1);
 assert.equal(db.queries.filter(q=>q[0].startsWith("REVOKE")).length,1);
 await assert.rejects(acquireTemporaryOwnerRole(fake(),{role:"indexer_api_read",schema:"api"}),/ADMIN OPTION/);
 await assert.rejects(acquireTemporaryOwnerRole(fake({admin:true,inherited:true}),{role:"indexer_api_read",schema:"api"}),/without inherited runtime owner/);
 const existing=fake({canSet:true});
 assert.equal((await acquireTemporaryOwnerRole(existing,{role:"indexer_api_read",schema:"api"})).added,false);
});

test("trusted Supabase BYPASSRLS non-superuser can perform scoped owner maintenance",async()=>{
 const db=fake({admin:true,bypassRls:true});
 const lease=await acquireTemporaryOwnerRole(db,{role:"chat_api_runtime_owner",schema:"app"});
 assert.equal(lease.added,true);
 await releaseTemporaryOwnerRole(db,lease);
});

test("approved Owner recipe cannot smuggle arbitrary dynamic DDL in DO / CALL / SELECT",()=>{
 const policy=createOwnerMaintenancePolicy({recipes:[
  {name:"approved",role:"chat_api_runtime_owner",schema:"app",functionName:"approved",mode:"set-role"}
 ]});
 const base="GRANT CREATE ON SCHEMA app TO chat_api_runtime_owner; SET LOCAL ROLE chat_api_runtime_owner; "+
  "CREATE OR REPLACE FUNCTION app.approved() RETURNS int LANGUAGE sql AS 'SELECT 1'; "+
  "RESET ROLE; REVOKE CREATE ON SCHEMA app FROM chat_api_runtime_owner;";
 for(const extra of [
  "DO $$ BEGIN EXECUTE 'DROP TABLE app.messages'; END $$;",
  "CALL app.untrusted();",
  "SELECT app.privileged_write();",
  "TRUNCATE app.messages;",
 ]) assert.throws(()=>policy.forCandidate("approved",base+" "+extra),/forbids extra SQL statement/);
});
test("explicitly versioned historic DO check stays compatible, but never permits a new AI candidate",()=>{
 const version="20261120163709_realtime_outbox_claim_owner_fix";
 const policy=createOwnerMaintenancePolicy({legacyThrough:"20261120160111_old",legacyDoVersions:[version],recipes:[
  {name:"realtime_outbox_claim_owner_fix",role:"chat_api_runtime_owner",schema:"app",functionName:"claim_realtime_events",mode:"set-role",version}
 ]});
 const migration="DO $$ BEGIN IF NOT pg_has_role(current_user,'chat_api_runtime_owner','SET') THEN RAISE EXCEPTION 'missing'; END IF; END $$; "+
  "GRANT CREATE ON SCHEMA app TO chat_api_runtime_owner; SET LOCAL ROLE chat_api_runtime_owner; "+
  "CREATE OR REPLACE FUNCTION app.claim_realtime_events() RETURNS int LANGUAGE sql AS 'SELECT 1'; "+
  "RESET ROLE; REVOKE CREATE ON SCHEMA app FROM chat_api_runtime_owner;";
 assert.equal(policy.forMigration({version,sql:migration}).role,"chat_api_runtime_owner");
 assert.throws(()=>policy.forCandidate("realtime_outbox_claim_owner_fix",migration),/forbids extra SQL statement/);
 assert.throws(()=>policy.forMigration({version:"20261122120000_realtime_outbox_claim_owner_fix",sql:migration}),/forbids extra SQL statement|requires approved recipe/);
});


test("service-only reader recipe permits only its exact EXECUTE ACL and final PostgREST reload",()=>{
 const policy=createOwnerMaintenancePolicy({recipes:[{
   name:"admin_dead_letter_list_v1",role:"chat_api_runtime_owner",schema:"app",
   functionName:"admin_list_realtime_dead_letters_v1",mode:"transfer",
   serviceExecuteRole:"service_role",notifyPostgrest:true
 }]});
 const ddl="GRANT CREATE ON SCHEMA app TO chat_api_runtime_owner; "+
   "CREATE FUNCTION app.admin_list_realtime_dead_letters_v1(p_page integer DEFAULT 0) "+
   "RETURNS integer LANGUAGE sql AS 'SELECT 1'; "+
   "REVOKE ALL ON FUNCTION app.admin_list_realtime_dead_letters_v1(integer) "+
   "FROM PUBLIC, anon, authenticated, service_role; "+
   "GRANT EXECUTE ON FUNCTION app.admin_list_realtime_dead_letters_v1(integer) TO service_role; "+
   "ALTER FUNCTION app.admin_list_realtime_dead_letters_v1(integer) OWNER TO chat_api_runtime_owner; "+
   "REVOKE CREATE ON SCHEMA app FROM chat_api_runtime_owner; "+
   "NOTIFY pgrst, 'reload schema';";
 assert.equal(policy.forCandidate("admin_dead_letter_list_v1",ddl).serviceExecuteRole,"service_role");
 assert.throws(()=>policy.forCandidate("other",ddl),/approved recipe/);
 assert.throws(()=>policy.forCandidate("admin_dead_letter_list_v1",ddl.replace(
   "TO service_role;","TO authenticated;")) ,/forbids extra SQL statement|requires exact service EXECUTE/);
 assert.throws(()=>policy.forCandidate("admin_dead_letter_list_v1",ddl.replace(
   "REVOKE ALL ON FUNCTION","REVOKE EXECUTE ON FUNCTION")) ,/forbids extra SQL statement|requires exact service EXECUTE/);
 assert.throws(()=>policy.forCandidate("admin_dead_letter_list_v1",ddl+" GRANT SELECT ON app.realtime_event_outbox TO service_role;"),
   /forbids extra SQL statement/);
 assert.throws(()=>policy.forCandidate("admin_dead_letter_list_v1",ddl.replace(
   "NOTIFY pgrst, 'reload schema';","NOTIFY pgrst, 'bad';")),/final PostgREST/);
 assert.throws(()=>policy.forCandidate("admin_dead_letter_list_v1",ddl.replace(
   "REVOKE CREATE ON SCHEMA app FROM chat_api_runtime_owner;","")),/temporary CREATE/);
});
