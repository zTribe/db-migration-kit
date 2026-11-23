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
  assert.equal(portableReviewDeltaMatches(reviewed,observed),true);
});
test("portable guard rejects missing, extra or revoked privileges",()=>{
  const before=runtimeBase;
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[change(before,before)]}),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(before,before.slice(0,-1)+","+added+",anon=X/@migration-role}")
  ]}),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(before,before.replace("anon=X/@migration-role,","").slice(0,-1)+","+added+"}")
  ]}),false);
});
test("portable guard rejects wrong grantor, changed grant options, object definition and unsafe ACL syntax",()=>{
  const after=runtimeBase.slice(0,-1)+","+added+"}";
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(runtimeBase,after.replace(added,"chat_api_runtime_owner=X/postgres"))
  ]}),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(runtimeBase,after.replace(added,"chat_api_runtime_owner=X*/@migration-role"))
  ]}),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(runtimeBase,after,{identity:["app","other_function",""]})
  ]}),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(runtimeBase,after,{desired:{...observed.changes[0].desired,security_definer:true}})
  ]}),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,changes:[
    change(runtimeBase,'{"chat_api_runtime_owner=X/@migration-role"}')
  ]}),false);
  assert.equal(portableReviewDeltaMatches(reviewed,{...observed,structure:[{section:"policies"}]}),false);
});
