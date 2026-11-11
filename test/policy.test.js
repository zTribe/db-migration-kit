import test from "node:test";
import assert from "node:assert/strict";
import { evaluateSecurityPolicy, buildSecurityAudit } from "../src/index.js";

const snapshot = {
  schemas: ["app"],
  tables: [{schema_name:"app",relname:"messages",relrowsecurity:true,relforcerowsecurity:true,owner_name:"db_owner"}],
  functions: [{oid:42,schema_name:"app",proname:"safe_fn",identity_args:"",security_definer:true,owner_name:"api_owner",proconfig:["search_path=pg_catalog, pg_temp"],public_execute:false}],
  roles: [{rolname:"anon",rolsuper:false,rolbypassrls:false}],
  privileges: {
    schemas: {anon:{app:{USAGE:false,CREATE:false}}},
    tables: {anon:{"app.messages":{SELECT:false,INSERT:false,UPDATE:false,DELETE:false,TRUNCATE:false,REFERENCES:false,TRIGGER:false}}},
    functions: {anon:{"app.safe_fn()":{EXECUTE:false}}},
  },
};
test("pure policy evaluates snapshots without any PostgreSQL connection", () => {
  const rules = {
    schemas:["app"],requiredTables:["app.messages"],requireRlsOn:["app.messages"],requireForceRlsOn:["app.messages"],
    requiredFunctions:["app.safe_fn()"],allowedDefinerOwners:["api_owner"],
    expectedDefinerSearchPaths:{"app.safe_fn()":"pg_catalog, pg_temp"},
    deniedExecuteRoles:["anon"],deniedTableDmlRoles:["anon"],deniedTableSelectRoles:["anon"],
    deniedSchemaUsageRoles:["anon"],deniedSchemaCreateRoles:["anon"],
    requiredRoles:["anon"],forbidSuperuserRoles:["anon"],forbidBypassRlsRoles:["anon"],
  };
  const passed = evaluateSecurityPolicy(snapshot, rules);
  assert.deepEqual(passed,[]);
  const report=buildSecurityAudit(snapshot,rules,passed);
  assert.equal(report.ok,true);
  assert.equal(report.summary.tables,1);
  const mutated=structuredClone(snapshot);
  mutated.tables[0].relrowsecurity=false;
  mutated.functions[0].public_execute=true;
  mutated.privileges.tables.anon["app.messages"].INSERT=true;
  mutated.roles[0].rolbypassrls=true;
  const failures=evaluateSecurityPolicy(mutated,rules);
  assert.ok(failures.some(x=>x.includes("RLS is disabled")));
  assert.ok(failures.some(x=>x.includes("PUBLIC can EXECUTE")));
  assert.ok(failures.some(x=>x.includes("effective INSERT")));
  assert.ok(failures.some(x=>x.includes("BYPASSRLS")));
  const failed=buildSecurityAudit(mutated,rules,failures);
  assert.equal(failed.ok,false);
  assert.equal(failed.diagnostics.length,failures.length);
  assert.ok(failed.diagnostics.every(item=>item.code==="RUNTIME_SECURITY_POLICY_VIOLATION"));
});
