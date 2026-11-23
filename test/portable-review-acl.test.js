import test from "node:test";
import assert from "node:assert/strict";
import { portableReviewDeltaMatches, portablePreconditionMatches } from "../src/guarded-plan.js";

const reviewedBase = "{postgres=X/postgres,anon=X/postgres,authenticated=X/postgres,service_role=X/postgres,@migration-role=X*/postgres}";
const runtimeBase = "{@migration-role=X/@migration-role,anon=X/@migration-role,authenticated=X/@migration-role,service_role=X/@migration-role}";
const added = "chat_api_runtime_owner=X/@migration-role";

function change(before, after, overrides={}) {
  const row = acl => ({ schema:"app",name:"jwt_wallet",arguments:"",
    owner:"@migration-role",security_definer:false,configuration:null,acl });
  return {
    section:"functions",identity:["app","jwt_wallet",""],
    previous:row(before),desired:row(after),sql:null,...overrides
  };
}
const reviewedChange = change(reviewedBase, reviewedBase.slice(0,-1)+","+added+"}");
reviewedChange.previous.owner = "postgres";
reviewedChange.desired.owner = "postgres";
const reviewed = { changes:[reviewedChange], structure:[] };
const observed = { changes:[change(runtimeBase, runtimeBase.slice(0,-1)+","+added+"}")], structure:[] };

test("portable guard accepts a verified historical owner/migrator overlap",()=>{
  assert.equal(portableReviewDeltaMatches(reviewed,observed,"postgres"),true);
});
test("portable guard rejects missing, extra or revoked privileges",()=>{
  const before=runtimeBase;
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[change(before,before)]},"postgres"),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(before,before.slice(0,-1)+","+added+",unexpected_role=X/@migration-role}")
  ]},"postgres"),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(before,before.replace("anon=X/@migration-role,","").slice(0,-1)+","+added+"}")
  ]},"postgres"),false);
});
test("portable guard rejects wrong grantor, changed grant options, object definition and unsafe ACL syntax",()=>{
  const after=runtimeBase.slice(0,-1)+","+added+"}";
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(runtimeBase,after.replace(added,"chat_api_runtime_owner=X/unrelated_grantor"))
  ]},"postgres"),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(runtimeBase,after.replace(added,"chat_api_runtime_owner=X*/@migration-role"))
  ]},"postgres"),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(runtimeBase,after,{identity:["app","other_function",""]})
  ]},"postgres"),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(runtimeBase,after,{desired:{...observed.changes[0].desired,security_definer:true}})
  ]},"postgres"),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(runtimeBase,'{"chat_api_runtime_owner=X/@migration-role"}')
  ]},"postgres"),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,structure:[{section:"policies"}]},"postgres"),false);
});

test("portable guard rejects pre-existing privilege drift even if no SQL changes it",()=>{
  const extra="outside_role=X/@migration-role";
  const base=runtimeBase.slice(0,-1)+","+extra+"}";
  const after=base.slice(0,-1)+","+added+"}";
  assert.equal(portableReviewDeltaMatches(reviewed,
    {changes:[change(base,after)],structure:[]},"postgres"),false);
});
test("portable guard only permits identity overlap for the actual migrator",()=>{
  assert.equal(portableReviewDeltaMatches(reviewed,observed,"some_other_migrator"),false);
});

test("portable guard rejects unrelated owner even when the ACL is otherwise identical",()=>{
  const wrong=change(runtimeBase,runtimeBase.slice(0,-1)+","+added+"}",{
    previous:{...observed.changes[0].previous,owner:"other_owner"},
    desired:{...observed.changes[0].desired,owner:"other_owner"}
  });
  assert.equal(portableReviewDeltaMatches(reviewed,{changes:[wrong],structure:[]},"postgres"),false);
});

test("portable precondition verifies affected function's complete before-state",()=>{
  const row={...observed.changes[0].previous};
  const state=permissions=>({permissions:{functions:permissions}});
  const changeRef={section:"functions",identity:["app","jwt_wallet",""]};
  const expected=state([row]);
  assert.equal(portablePreconditionMatches(expected,state([row]),[changeRef],"postgres"),true);
  assert.equal(portablePreconditionMatches(expected,state([{...row,acl:row.acl.slice(0,-1)+",unauthorized=X/@migration-role}"}]),[changeRef],"postgres"),false);
  assert.equal(portablePreconditionMatches(expected,state([{...row,owner:"different_owner"}]),[changeRef],"postgres"),false);
  assert.equal(portablePreconditionMatches(expected,state([]),[changeRef],"postgres"),false);
  assert.equal(portablePreconditionMatches(expected,state([row,row]),[changeRef],"postgres"),false);
});

test("portable precondition allows real migrator=historical owner, but rejects drift",()=>{
  const ref={section:"functions",identity:["app","jwt_wallet",""]};
  const state=functions=>({permissions:{functions}});
  assert.equal(portablePreconditionMatches(
    state([reviewed.changes[0].previous]),
    state([observed.changes[0].previous]),[ref],"postgres"),true);
  assert.equal(portablePreconditionMatches(
    state([reviewed.changes[0].previous]),
    state([{...observed.changes[0].previous,acl:runtimeBase.slice(0,-1)+",intruder=X/@migration-role}"}]),[ref],"postgres"),false);
  assert.equal(portablePreconditionMatches(
    state([{...reviewed.changes[0].previous,owner:"other_owner"}]),
    state([observed.changes[0].previous]),[ref],"postgres"),false);
});

test("portable guard still accepts a one-to-one portable migration identity",()=>{
  const before="{anon=X/@migration-role,@migration-role=X/@migration-role}";
  const after=before.slice(0,-1)+","+added+"}";
  const same={changes:[change(before,after)],structure:[]};
  assert.equal(portableReviewDeltaMatches(same,same,"postgres"),true);
});

test("portable guard refuses alias collision when migrator is not historical function owner",()=>{
  const other={changes:[{
    ...reviewed.changes[0],
    previous:{...reviewed.changes[0].previous,owner:"other_owner"},
    desired:{...reviewed.changes[0].desired,owner:"other_owner"}
  }],structure:[]};
  assert.equal(portableReviewDeltaMatches(other,observed,"postgres"),false);
});
