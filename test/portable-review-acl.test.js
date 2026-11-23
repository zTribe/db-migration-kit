import test from "node:test";
import assert from "node:assert/strict";
import { portableReviewDeltaMatches } from "../src/guarded-plan.js";

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
const reviewed = { changes:[change(reviewedBase, reviewedBase.slice(0,-1)+","+added+"}")], structure:[] };
const observed = { changes:[change(runtimeBase, runtimeBase.slice(0,-1)+","+added+"}")], structure:[] };

test("portable guard accepts identical new EXECUTE grant despite unchanged historical ACL grantor",()=>{
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
