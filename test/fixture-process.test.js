import test from "node:test";
import assert from "node:assert/strict";
import { safeTestEnvironment,confirmTargetedFixtureRan } from "../src/fixture-process.js";
test("disposable tests scrub real database credentials even if shell has them",()=>{
 const env=safeTestEnvironment({
  DATABASE_URL:"postgres://prod.example",MIGRATION_DATABASE_URL:"postgres://prod",
  PGHOST:"prod",PGPASSWORD:"secret",CHAT_TEST_DATABASE_URL:"postgres://old",PATH:"/usr/bin",
 },{CHAT_TEST_DATABASE_URL:"postgres://postgres@127.0.0.1:5432/test"});
 assert.equal(env.DATABASE_URL,undefined);assert.equal(env.PGHOST,undefined);
 assert.equal(env.PGPASSWORD,undefined);assert.equal(env.MIGRATION_DATABASE_URL,undefined);
 assert.equal(env.PATH,"/usr/bin");
 assert.equal(env.CHAT_TEST_DATABASE_URL,"postgres://postgres@127.0.0.1:5432/test");
});
test("pass zero and all-skipped TAP are hard failures",()=>{
 for(const tap of ["# tests 0\n# pass 0\n# fail 0\n",
  "# tests 1\n# pass 0\n# fail 0\n# skipped 1\n",
  "TAP version 13\n"]) {
  assert.throws(()=>confirmTargetedFixtureRan(tap,"chat"),/did not execute/);
 }
 assert.doesNotThrow(()=>confirmTargetedFixtureRan(
  "TAP version 13\nok 1 - PR migrations upgrade Git baseline\n# tests 15\n# pass 1\n# fail 0\n# skipped 14\n",
  "indexer","^PR migrations upgrade"));
 assert.throws(()=>confirmTargetedFixtureRan("# tests 3\n# pass 2\n# fail 1\n","chat"),/did not execute/);
});

test("passing unrelated tests cannot conceal a skipped required PG17 migration fixture",()=>{
 const result="TAP version 13\nok 1 - unrelated smoke check\n"+
  "ok 2 - PR migrations upgrade Git baseline # SKIP no database\n"+
  "# tests 2\n# pass 1\n# fail 0\n# skipped 1\n";
 assert.throws(()=>confirmTargetedFixtureRan(result,"chat","^PR migrations upgrade"),/did not execute/);
 const good="TAP version 13\nok 1 - PR migrations upgrade Git baseline\n"+
  "# tests 1\n# pass 1\n# fail 0\n# skipped 0\n";
 assert.doesNotThrow(()=>confirmTargetedFixtureRan(good,"chat","^PR migrations upgrade"));
});
