import test from "node:test";
import assert from "node:assert/strict";
import { withMigrationLock } from "../src/lock.js";

function fixture(workError) {
  const queries = [], releases = [];
  const client = {
    async query(sql) {
      queries.push(sql);
      if (/try_advisory_lock/.test(sql)) return { rows: [{locked:true}] };
      return { rows: [] };
    },
    release(err) { releases.push(err); },
  };
  return { pool:{async connect(){return client;}}, queries, releases, work:()=>{if(workError)throw workError;return 7;} };
}

test("successful migration releases pooled connection normally", async () => {
 const f=fixture();
 assert.equal(await withMigrationLock(f.pool,{lockName:"kit-success"},f.work),7);
 assert.equal(f.releases.length,1);
 assert.equal(f.releases[0],undefined);
 assert.equal(f.queries.filter(sql=>/advisory_unlock/.test(sql)).length,1);
});

test("failed migration destroys pooled session after unlocking", async () => {
 const error = new Error("DDL rolled back");
 const f=fixture(error);
 await assert.rejects(withMigrationLock(f.pool,{lockName:"kit-failure"},f.work),error);
 assert.equal(f.releases.length,1);
 assert.equal(f.releases[0],error);
 assert.equal(f.queries.filter(sql=>/advisory_unlock/.test(sql)).length,1);
});
