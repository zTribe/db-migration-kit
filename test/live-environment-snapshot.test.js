import test from "node:test";
import assert from "node:assert/strict";
import {parseLiveEnvironmentSnapshot,compareLiveEnvironmentSnapshots} from "../src/live-environment-snapshot.js";
function snapshot(){return {
 postgres_version:"17.11",database_acl:{owner:"postgres",acl:"{postgres=CTc/postgres}"},
 roles:[{rolname:"postgres",rolsuper:false}],memberships:[],schemas:[],relations:[],
 column_acls:[],functions:[],policies:[],default_acls:[],extensions:[],
 migration_ledger:[{version:"001_test",name:"001_test.sql",checksum:"a".repeat(64),source:"migration",applied_at:"2026-01-01"}]
};}
test("JSON and RFC4180 multiline SQL Editor CSV both parse",()=>{
 const json=JSON.stringify(snapshot(),null,2);
 const csv="complete_snapshot\r\n\""+json.replaceAll('"','""')+"\"\r\n";
 assert.deepEqual(parseLiveEnvironmentSnapshot(csv),snapshot());
 assert.deepEqual(parseLiveEnvironmentSnapshot(json),snapshot());
 assert.throws(()=>parseLiveEnvironmentSnapshot(csv+'"another"'),/exactly one/);
});
test("applied_at ignored; baseline versus migration is informational",()=>{
 const dev=snapshot(),prod=snapshot();
 prod.migration_ledger[0].source="baseline";
 prod.migration_ledger[0].applied_at="2026-01-02";
 const out=compareLiveEnvironmentSnapshots(dev,prod);
 assert.equal(out.status,"aligned");
 assert.equal(out.counts.information,1);
});
test("version or checksum drift blocks release",()=>{
 const dev=snapshot(),prod=snapshot();
 prod.migration_ledger[0].checksum="b".repeat(64);
 assert.equal(compareLiveEnvironmentSnapshots(dev,prod).status,"block");
 prod.migration_ledger=[];
 assert.equal(compareLiveEnvironmentSnapshots(dev,prod).status,"block");
});
test("extra production-only audit role and ACL require review",()=>{
 const dev=snapshot(),prod=snapshot();
 prod.roles.push({rolname:"main_migration_audit",rolsuper:false});
 prod.database_acl.acl+=",main_migration_audit=c/postgres";
 const out=compareLiveEnvironmentSnapshots(dev,prod);
 assert.equal(out.status,"review");
 assert.equal(out.counts.permission_review,2);
});
test("function settings are not echoed in diagnostics",()=>{
 const dev=snapshot(),prod=snapshot();
 const fn={schema_name:"app",name:"f",arguments:"",function_settings:["token=secret-value"]};
 dev.functions=[fn];prod.functions=[{...fn,function_settings:["token=other-secret"]}];
 const out=compareLiveEnvironmentSnapshots(dev,prod);
 assert.equal(out.counts.permission_review,1);
 assert.ok(!JSON.stringify(out).includes("secret-value"));
 assert.equal(out.findings[0].fields[0],"function_settings");
});
test("duplicate identities rejected",()=>{
 const dev=snapshot(),prod=snapshot();dev.roles.push(dev.roles[0]);
 assert.throws(()=>compareLiveEnvironmentSnapshots(dev,prod),/Duplicate roles/);
});
