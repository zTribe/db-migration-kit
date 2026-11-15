import test from "node:test";
import assert from "node:assert/strict";
import {planDependencyImpact,assertDependencyImpactReviewed} from "../src/dependency-impact.js";
const rules=[
 {id:"token-meta",kind:"cache",sources:[{kind:"table",name:"chain.tokens"},{kind:"function",name:"api.token_display_metadata"}]},
 {id:"candles",kind:"cache",sources:[{kind:"table",name:"chain.candles"},{kind:"function",name:"api.token_candles"}]},
 {id:"limiter",kind:"security",sources:[{kind:"table",name:"app.api_rate_limit_buckets"}]},
];
test("unrelated table changes do not force Redis changes",()=>{
 const result=planDependencyImpact({rules,sql:"ALTER TABLE app.messages ADD COLUMN note text;"});
 assert.equal(result.requiresReview,false);
 assert.deepEqual(result.affected,[]);
 assert.doesNotThrow(()=>assertDependencyImpactReviewed(result));
});
test("relevant SQL migration produces per-cache blocking review",()=>{
 const result=planDependencyImpact({rules,sql:"ALTER TABLE chain.candles ADD COLUMN fee numeric; UPDATE chain.tokens SET name='new';"});
 assert.deepEqual(result.affected.map(x=>x.id),["token-meta","candles"]);
 assert.throws(()=>assertDependencyImpactReviewed(result),/requires/);
 const review={digest:result.digest,reason:"Reviewed data changes",
  decisions:result.affected.map(x=>({id:x.id,action:"versioned-rollout",reason:"Bump epoch after backfill"}))};
 assert.doesNotThrow(()=>assertDependencyImpactReviewed(result,review));
 assert.throws(()=>assertDependencyImpactReviewed(result,{...review,digest:"incorrect"}));
});
test("plan output permission and column changes are included",()=>{
 const result=planDependencyImpact({rules,plan:{changes:[{section:"objects",identity:["app","api_rate_limit_buckets"]}],structure:[{section:"columns",key:"chain.candles.fee"}]}});
 assert.deepEqual(result.affected.map(x=>x.id),["candles","limiter"]);
});
test("dynamic SQL is never silently classified as safe",()=>{
 const result=planDependencyImpact({rules,sql:"DO $$ BEGIN EXECUTE 'UPDATE chain.tokens SET name = ''x'''; END $$;"});
 assert.equal(result.uncertain,true);
 assert.equal(result.requiresReview,true);
 assert.throws(()=>assertDependencyImpactReviewed(result));
});
test("invalid manifests and duplicate identifiers are rejected",()=>{
 assert.throws(()=>planDependencyImpact({rules:[...rules,rules[0]]}),/Invalid dependency rule/);
 assert.throws(()=>planDependencyImpact({rules:[{id:"x",kind:"cache",sources:[{kind:"table",name:"bad"}]}]}),/Invalid dependency source/);
});
