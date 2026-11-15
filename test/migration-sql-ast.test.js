import test from "node:test";
import assert from "node:assert/strict";
import { planDependencyImpactAst, assertDependencyImpactReviewed } from "../src/dependency-impact.js";

const rules = [
  {id:"metadata",kind:"cache",sources:[{kind:"table",name:"chain.tokens"}]},
  {id:"limiter",kind:"security",sources:[{kind:"table",name:"app.api_rate_limit_buckets"}]},
];

test("AST: semicolons in literals and comments cannot invent migration touches",async()=>{
  const report=await planDependencyImpactAst({rules,
    sql:"-- UPDATE chain.tokens;\nALTER TABLE app.messages ADD COLUMN note text DEFAULT 'UPDATE chain.tokens;';"});
  assert.deepEqual(report.affected,[]);
  assert.equal(report.uncertain,false);
  assert.equal(report.releaseApproved,false);
});

test("AST: quoted fully-qualified DML target is detected",async()=>{
  const report=await planDependencyImpactAst({rules,
    sql:'UPDATE "chain"."tokens" SET symbol = \'X\';'});
  assert.deepEqual(report.affected.map(x=>x.id),["metadata"]);
  assert.equal(report.requiresReview,true);
  assert.throws(()=>assertDependencyImpactReviewed(report),/requires/);
});

test("AST: data-changing DDL is traced without string splitting",async()=>{
  const report=await planDependencyImpactAst({rules,
    sql:"ALTER TABLE app.api_rate_limit_buckets ADD COLUMN extra integer;"});
  assert.deepEqual(report.affected.map(x=>x.id),["limiter"]);
});

test("AST: dynamic SQL fails closed even if the affected table is hidden",async()=>{
  const report=await planDependencyImpactAst({rules,
    sql:"DO $$ BEGIN EXECUTE 'UPDATE chain.tokens SET symbol = ''X'''; END $$;"});
  assert.equal(report.uncertain,true);
  assert.equal(report.requiresReview,true);
  assert.throws(()=>assertDependencyImpactReviewed(report),/requires/);
});

test("AST: unqualified table name requires review",async()=>{
  const report=await planDependencyImpactAst({rules,sql:"ALTER TABLE tokens ADD COLUMN note text;"});
  assert.equal(report.uncertain,true);
  assert.equal(report.requiresReview,true);
});

test("AST: syntax errors must never silently become safe impact reports",async()=>{
  await assert.rejects(()=>planDependencyImpactAst({rules,sql:"ALTER TABLE chain.tokens ADD COLUMN"}));
});

test("AST: exact-digest review is still mandatory for affected objects",async()=>{
  const report=await planDependencyImpactAst({rules,sql:"UPDATE chain.tokens SET symbol = 'A';"});
  const review={digest:report.digest,reason:"Data compatibility reviewed",
    decisions:[{id:"metadata",action:"versioned-rollout",reason:"Rotate cache epoch"}]};
  assert.doesNotThrow(()=>assertDependencyImpactReviewed(report,review));
  assert.throws(()=>assertDependencyImpactReviewed(report,{...review,digest:"stale"}));
});
