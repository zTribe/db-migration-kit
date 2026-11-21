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
 assert.throws(()=>chat.forCandidate("list_v1",sql+" GRANT chat_api_runtime_owner TO current_user;"),/forbids SQL role grants/);
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
function fake({admin=false,canSet=false,inherited=false}={}) {
 const queries=[];let roleSet=canSet;
 return {queries,async query(sql,args=[]) {
  queries.push([sql,args]);
  if(sql.includes("session_user AS login"))return{rows:[{role:"migrator",login:"migrator",rolsuper:false,rolbypassrls:false,inherited,can_set:roleSet,admin_option:admin,self_grant:false}]};
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
 await assert.rejects(acquireTemporaryOwnerRole(fake({admin:true,inherited:true}),{role:"indexer_api_read",schema:"api"}),/non-inheriting/);
 const existing=fake({canSet:true});
 assert.equal((await acquireTemporaryOwnerRole(existing,{role:"indexer_api_read",schema:"api"})).added,false);
});
