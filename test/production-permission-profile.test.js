import test from "node:test";
import assert from "node:assert/strict";
import { deriveProductionPermissionProfile,compareProductionPermissionProfiles,renderDisposableRoleSetup,renderDisposableAclSetup,verifyProductionPermissionFixture } from "../src/production-permission-profile.js";
function sample(){
 return {postgres_version:"17.11",roles:[
  {rolname:"postgres",rolcanlogin:true,rolsuper:false,rolcreatedb:true,rolcreaterole:true,rolbypassrls:true,rolinherit:true,rolreplication:true},
  {rolname:"owner",rolcanlogin:false,rolsuper:false,rolcreatedb:false,rolcreaterole:false,rolbypassrls:false,rolinherit:false,rolreplication:false}
 ],memberships:[{member:"postgres",parent:"owner",admin_option:true,inherit_option:"false",set_option:"false"}],
 schemas:[{schema_name:"app",owner:"postgres",acl:"{postgres=UC/postgres,owner=U/postgres}"}],
 database_acl:{owner:"postgres",acl:"{=Tc/postgres,postgres=CTc/postgres}"},
 relations:[{schema_name:"app",name:"records",relkind:"r",owner:"postgres",rls:true,force_rls:false,acl:null}],
 functions:[],column_acls:[],policies:[],migration_ledger:[{version:"001_chain",name:"001_chain.sql",checksum:"a".repeat(64),source:"migration"}]};
}
const cfg={project:"chat",schemas:["app"],roles:["postgres","owner"]};
test("scoped Production profile fingerprints real Owner and grants",()=>{
 const expected=deriveProductionPermissionProfile(sample(),cfg);
 assert.equal(expected.catalog.relations.count,1);
 assert.equal(compareProductionPermissionProfiles(expected,deriveProductionPermissionProfile(sample(),cfg)).ok,true);
 const drift=sample();drift.relations[0].owner="owner";
 assert.equal(compareProductionPermissionProfiles(expected,deriveProductionPermissionProfile(drift,cfg)).ok,false);
});
test("schema ACL ordering is ignored, extra privilege and SET drift are rejected",()=>{
 const expected=deriveProductionPermissionProfile(sample(),cfg);
 const order=sample();order.schemas[0].acl="{owner=U/postgres,postgres=UC/postgres}";
 assert.equal(compareProductionPermissionProfiles(expected,deriveProductionPermissionProfile(order,cfg)).ok,true);
 const membership=sample();membership.memberships[0].set_option="true";
 assert.equal(compareProductionPermissionProfiles(expected,deriveProductionPermissionProfile(membership,cfg)).ok,false);
 const db=sample();db.database_acl.acl="{=Tc/postgres,postgres=CTc/postgres,owner=C/postgres}";
 assert.equal(compareProductionPermissionProfiles(expected,deriveProductionPermissionProfile(db,cfg)).ok,false);
});
test("Docker role setup never silently promotes postgres to superuser",()=>{
 const expected=deriveProductionPermissionProfile(sample(),cfg);
 const sql=renderDisposableRoleSetup(expected);
 assert.match(sql,/ALTER ROLE "postgres".*NOSUPERUSER/);
 assert.match(sql,/GRANT "owner" TO "postgres" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE/);
 const unsafe=structuredClone(expected);unsafe.roles[0].rolsuper=true;
 assert.throws(()=>renderDisposableRoleSetup(unsafe),/SUPERUSER/);
});
test("baseline refuses wrong PG major or absent role",()=>{
 assert.throws(()=>deriveProductionPermissionProfile({...sample(),postgres_version:"18.1"},cfg),/PG17/);
 const missing=sample();missing.roles.pop();
 assert.throws(()=>deriveProductionPermissionProfile(missing,cfg),/Production role missing/);
});


test("Production policy roles are read as a real text[] array, not name[] text", async () => {
 const snapshot=sample();
 snapshot.policies=[{
  schemaname:"app",tablename:"records",policyname:"records_select",permissive:"PERMISSIVE",
  roles:["postgres"],cmd:"SELECT",using_hash:"abc",check_hash:"def"
 }];
 const profile=deriveProductionPermissionProfile(snapshot,cfg);
 let lookedUpPolicy=false;
 const client={async query(sql){
  if(sql.startsWith("BEGIN")||sql==="ROLLBACK")return {rows:[]};
  if(sql.includes("server_version_num"))return {rows:[{major:17}]};
  if(sql.includes("server_version"))return {rows:[{v:snapshot.postgres_version}]};
  if(sql.includes("FROM pg_catalog.pg_roles"))return {rows:snapshot.roles};
  if(sql.includes("FROM pg_catalog.pg_auth_members"))return {rows:snapshot.memberships.map(x=>({...x,inherit_option:false,set_option:false}))};
  if(sql.includes("FROM pg_catalog.pg_namespace"))return {rows:snapshot.schemas};
  if(sql.includes("FROM pg_catalog.pg_class"))return {rows:snapshot.relations};
  if(sql.includes("FROM pg_catalog.pg_attribute"))return {rows:snapshot.column_acls};
  if(sql.includes("FROM pg_catalog.pg_proc"))return {rows:snapshot.functions};
  if(sql.includes("FROM pg_catalog.pg_policies")){
   assert.match(sql,/roles::text\[\] AS roles/);
   lookedUpPolicy=true;
   return {rows:snapshot.policies};
  }
  if(sql.includes("schema_migrations ORDER BY version"))return {rows:snapshot.migration_ledger};
  if(sql.includes("FROM pg_catalog.pg_database"))return {rows:[snapshot.database_acl]};
  throw Error("Unexpected production catalog query: "+sql);
 }};
 const result=await verifyProductionPermissionFixture(client,profile);
 assert.equal(lookedUpPolicy,true);
 assert.equal(result.ok,true);
 const drift=structuredClone(snapshot);
 drift.policies[0].roles=["owner"];
 assert.equal(compareProductionPermissionProfiles(profile,deriveProductionPermissionProfile(drift,cfg)).ok,false,
  "role membership drift must still change the policy hash");
});

test("Production baseline ledger mismatch fails rather than replaying future migrations",()=>{
 const profile=deriveProductionPermissionProfile(sample(),cfg);
 assert.equal(profile.baseline.version,"001_chain");
 const changed=sample();changed.migration_ledger[0].checksum="b".repeat(64);
 assert.equal(compareProductionPermissionProfiles(profile,deriveProductionPermissionProfile(changed,cfg)).ok,false);
});

test("disposable ACL fixture accepts explicitly recorded Dev role grants, never a synthetic or untrusted source",()=>{
 const dev={...deriveProductionPermissionProfile(sample(),cfg),source:"dev"};
 assert.match(renderDisposableAclSetup(dev),/REVOKE ALL PRIVILEGES ON SCHEMA/);
 assert.throws(()=>renderDisposableAclSetup({...dev,source:"unreviewed"}),/reviewed Dev or Production/);
});
