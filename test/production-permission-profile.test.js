import test from "node:test";
import assert from "node:assert/strict";
import { deriveProductionPermissionProfile,compareProductionPermissionProfiles,renderDisposableRoleSetup } from "../src/production-permission-profile.js";
function sample(){
 return {postgres_version:"17.11",roles:[
  {rolname:"postgres",rolcanlogin:true,rolsuper:false,rolcreatedb:true,rolcreaterole:true,rolbypassrls:true,rolinherit:true,rolreplication:true},
  {rolname:"owner",rolcanlogin:false,rolsuper:false,rolcreatedb:false,rolcreaterole:false,rolbypassrls:false,rolinherit:false,rolreplication:false}
 ],memberships:[{member:"postgres",parent:"owner",admin_option:true,inherit_option:"false",set_option:"false"}],
 schemas:[{schema_name:"app",owner:"postgres",acl:"{postgres=UC/postgres,owner=U/postgres}"}],
 database_acl:{owner:"postgres",acl:"{=Tc/postgres,postgres=CTc/postgres}"},
 relations:[{schema_name:"app",name:"records",relkind:"r",owner:"postgres",rls:true,force_rls:false,acl:null}],
 functions:[],column_acls:[],policies:[]};
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
