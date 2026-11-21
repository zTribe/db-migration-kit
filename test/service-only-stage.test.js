import test from "node:test";
import assert from "node:assert/strict";
import { assertServiceOnlyFunctions } from "../src/runner.js";

function fixture(permissions) {
  const checked=[];
  const client={async query(_sql,[signature]){
    checked.push(signature);
    return {rows:permissions[signature]?[permissions[signature]]:[]};
  }};
  return {client,checked};
}
const valid={definer:true,anon:false,authenticated:false,service:true,public:false};
const unsafe={...valid,authenticated:true};

test("future service-only RPC may be absent during earlier guarded migration",async()=>{
  const f=fixture({"app.old_rpc()":valid});
  await assertServiceOnlyFunctions(f.client,["app.old_rpc()","app.future_rpc(integer)"],{allowMissing:true});
  assert.deepEqual(f.checked,["app.old_rpc()","app.future_rpc(integer)"]);
  await assert.rejects(
    assertServiceOnlyFunctions(f.client,["app.old_rpc()","app.future_rpc(integer)"]),
    /Service-only function policy failed: app.future_rpc\(integer\)/);
});
test("an existing unsafe service-only function fails even at intermediate checkpoint",async()=>{
  const f=fixture({"app.old_rpc()":unsafe});
  await assert.rejects(
    assertServiceOnlyFunctions(f.client,["app.old_rpc()","app.future_rpc(integer)"],{allowMissing:true}),
    /Service-only function policy failed: app.old_rpc\(\)/);
});
test("final checkpoint requires every configured service-only function and a strict ACL",async()=>{
  const f=fixture({"app.old_rpc()":valid,"app.future_rpc(integer)":valid});
  await assertServiceOnlyFunctions(f.client,["app.old_rpc()","app.future_rpc(integer)"]);
  const revoked=fixture({"app.old_rpc()":valid,"app.future_rpc(integer)":{...valid,service:false}});
  await assert.rejects(
    assertServiceOnlyFunctions(revoked.client,["app.old_rpc()","app.future_rpc(integer)"]),
    /Service-only function policy failed: app.future_rpc\(integer\)/);
});
