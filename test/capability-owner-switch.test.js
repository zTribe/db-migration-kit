import test from "node:test";
import assert from "node:assert/strict";
import { preflightMigrationCapabilities } from "../src/capability.js";

function fixture({set=false,usage=false,ownerCreate=false}={}) {
  return {async query(sql, args=[]) {
    if (sql.includes("current_user as role")) return {rows:[{role:"kit_migrator",superuser:false}]};
    if (sql.includes("pg_catalog.pg_has_role")) return {rows:[{signature:"app.claim_realtime_events(integer,integer)",owner:"chat_api_runtime_owner",can_alter:usage,can_set:set}]};
    if (sql.includes("has_schema_privilege")) return {rows:[{can_create:args[0]==="kit_migrator"||ownerCreate}]};
    throw Error(sql);
  }};
}
const fn="CREATE OR REPLACE FUNCTION app.claim_realtime_events(integer,integer) RETURNS integer LANGUAGE sql AS 'SELECT 1';";
const switching="GRANT CREATE ON SCHEMA app TO chat_api_runtime_owner; SET LOCAL ROLE chat_api_runtime_owner; "+fn+" RESET ROLE;";
test("explicit SET ROLE requires live SET membership",async()=>{
  await assert.rejects(preflightMigrationCapabilities(fixture(),switching),/cannot alter/);
  await preflightMigrationCapabilities(fixture({set:true}),switching);
  await assert.rejects(preflightMigrationCapabilities(fixture({set:true}),fn),/cannot alter/);
});
test("switching owner must have schema CREATE",async()=>{
  await assert.rejects(preflightMigrationCapabilities(fixture({set:true}),"SET LOCAL ROLE chat_api_runtime_owner; "+fn),/lacks CREATE/);
  await preflightMigrationCapabilities(fixture({set:true,ownerCreate:true}),"SET LOCAL ROLE chat_api_runtime_owner; "+fn);
});
test("RESET ROLE before DDL cannot authorize owner switch",async()=>{
  await assert.rejects(preflightMigrationCapabilities(fixture({set:true}),"SET LOCAL ROLE chat_api_runtime_owner; RESET ROLE; "+fn),/cannot alter/);
});
test("inherited owner still passes",async()=>{await preflightMigrationCapabilities(fixture({usage:true}),fn)});

test("new CREATE FUNCTION checks actual schema CREATE; legacy CREATE remains compatible",async()=>{
 const createFn="CREATE FUNCTION app.new_rpc() RETURNS integer LANGUAGE sql AS 'select 1';";
 const noCreate={async query(sql) {
   if(sql.includes("current_user as role"))return{rows:[{role:"kit_migrator",superuser:false}]};
   if(sql.includes("has_schema_privilege"))return{rows:[{can_create:false}]};
   throw Error(sql);
 }};
 await preflightMigrationCapabilities(noCreate,createFn);
 await assert.rejects(preflightMigrationCapabilities(noCreate,createFn,{future:true}),/lacks CREATE/);
});
test("future migration cannot trust self-granted owner privilege",async()=>{
 const sql="GRANT chat_api_runtime_owner TO current_user; "+fn;
 await preflightMigrationCapabilities(fixture(),sql); // historical compatibility
 await assert.rejects(preflightMigrationCapabilities(fixture(),sql,{future:true}),/cannot alter/);
});
test("future function checks ignore quoted SQL content",async()=>{
 await preflightMigrationCapabilities({async query(){throw Error("catalog must not be accessed");}},
   "SELECT 'CREATE OR REPLACE FUNCTION app.ghost()'; -- ALTER FUNCTION app.ghost()",{future:true});
});
