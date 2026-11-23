import test from "node:test";
import assert from "node:assert/strict";
import {buildPreDraftContext,parsePreDraftTarget} from "../src/pre-draft-context.js";
const snapshot={schema:null,permissions:{
 schemas:[{schema:"chain",owner:"postgres",acl:"{}"}],
 objects:[{schema:"chain",name:"market",kind:"r",owner:"postgres",rls:true,acl:"{}"}],
 functions:[{schema:"chain",name:"notify",arguments:"",owner:"indexer_api_read",security_definer:true,configuration:["search_path=pg_catalog, pg_temp"]},
 {schema:"chain",name:"overload",arguments:"a bigint",owner:"postgres"},{schema:"chain",name:"overload",arguments:"a text",owner:"postgres"}],
 policies:[{schema:"chain",tablename:"market",policyname:"market_select"}]}};
const profile={project:"indexer",source:"production",postgresMajor:17,migrationRole:"postgres",schemas:["chain"],
 roles:[{rolname:"postgres",rolsuper:false}],memberships:[{member:"postgres",parent:"indexer_api_read",admin_option:true,set_option:false,inherit_option:false}],
 baseline:{version:"066_archive_rpc_usage_hourly",count:67,checksum:"hash"}};
const run=(targets,o={})=>buildPreDraftContext({project:"indexer",snapshot,profile,targets,...o});
test("owner and role membership evidence are advisory",()=>{
 const r=run(["function:chain.notify()"]);
 assert.equal(r.approved,false);assert.equal(r.objects[0].recordedMembership.set,false);
 assert.ok(r.issues.some(x=>x.code==="OWNER_MISMATCH"));assert.ok(r.issues.some(x=>x.code==="EXPECTED_NOT_LIVE"));
});
test("relation shows policy and RLS facts",()=>{
 const r=run(["relation:chain.market"]);
 assert.equal(r.objects[0].recordedObject.rls,true);assert.equal(r.objects[0].policies[0].policyname,"market_select");
});
test("missing profile coverage blocks and overload requires signature",()=>{
 assert.equal(run(["relation:realtime.messages"]).blocked,true);
 assert.equal(run(["function:chain.overload"]).blocked,true);
 assert.equal(run(["function:chain.overload(a bigint)"]).objects[0].matched,1);
});
test("no inferred approval for unsafe input",()=>{
 assert.throws(()=>run([]),/At least one/);
 assert.throws(()=>parsePreDraftTarget("relation:../example"),/Expected/);
 assert.throws(()=>run(["relation:chain.market","relation:chain.market"]),/Duplicate/);
 assert.throws(()=>buildPreDraftContext({project:"chat",snapshot,profile,targets:["relation:chain.market"]}),/project profile/);
});

test("full Kit schema snapshot provides columns, indexes, trigger, and constraint evidence",()=>{
  const full={...snapshot,schema:{tables:[{schema_name:"chain",name:"market",kind:"r"}],
    columns:[{schema_name:"chain",table_name:"market",name:"lease_token",type:"uuid"}],
    constraints:[{schema_name:"chain",table_name:"market",name:"market_check",definition:"CHECK (true)"}],
    indexes:[{schema_name:"chain",table_name:"market",name:"market_idx",definition:"CREATE INDEX ..."}],
    triggers:[{schema_name:"chain",table_name:"market",name:"trg",definition:"CREATE TRIGGER ..."}],
    functions:[]}};
  const r=buildPreDraftContext({project:"indexer",snapshot:full,profile,targets:["relation:chain.market"]});
  assert.equal(r.objects[0].structuralCatalog.columns[0].name,"lease_token");
  assert.equal(r.objects[0].structuralCatalog.indexes.length,1);
  assert.equal(r.objects[0].structuralCatalog.triggers.length,1);
  assert.ok(!r.issues.some(x=>x.code==="SCHEMA_DEFINITIONS_MISSING"));
});
