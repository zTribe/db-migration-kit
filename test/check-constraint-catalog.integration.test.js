import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { compareSchemaCatalog, normalizeSchemaCatalog, planMigration, readTargetState } from "../src/index.js";

test("legacy validated CHECK snapshots stay stable while NOT VALID is a change", () => {
  const empty = {tables:[],columns:[],constraints:[],indexes:[],triggers:[],functions:[],policies:[],publications:[]};
  const row = {schema_name:"chain",table_name:"proposals",name:"proposals_kind",kind:"c",
    definition:"CHECK ((kind >= 0) AND (kind <= 6))"};
  const before = {...empty,constraints:[row]};
  const validated = {...empty,constraints:[{...row,validated:true}]};
  const notValid = {...empty,constraints:[{...row,validated:false}]};
  assert.deepEqual(normalizeSchemaCatalog(validated),normalizeSchemaCatalog(before));
  const diff = compareSchemaCatalog(before,notValid);
  assert.equal(diff.ok,false);
  assert.equal(diff.differences.length,1);
  assert.equal(diff.differences[0].section,"constraints");
});

test("PG17 captures CHECK expression changes and validation state for a reviewed migration", {
  skip: !process.env.PG_TEST_URL,
}, async () => {
  const client = new pg.Client({connectionString:process.env.PG_TEST_URL});
  await client.connect();
  try {
    await client.query("BEGIN");
    await client.query("CREATE SCHEMA kit_check_capture; CREATE TABLE kit_check_capture.proposals (kind smallint NOT NULL CONSTRAINT proposals_kind CHECK (kind BETWEEN 0 AND 6))");
    const capture = () => readTargetState(client,["kit_check_capture"]);
    const before = await capture();
    await client.query("ALTER TABLE kit_check_capture.proposals DROP CONSTRAINT proposals_kind");
    await client.query("ALTER TABLE kit_check_capture.proposals ADD CONSTRAINT proposals_kind CHECK (kind BETWEEN 0 AND 7) NOT VALID");
    const unvalidated = await capture();
    const widened = planMigration(before,unvalidated);
    assert.equal(widened.changes.length,0);
    assert.equal(widened.structure.length,1);
    assert.equal(widened.structure[0].section,"constraints");
    assert.equal(widened.structure[0].code,"CHANGED");
    assert.equal(unvalidated.schema.constraints.find(x=>x.name==="proposals_kind").validated,false);
    await client.query("ALTER TABLE kit_check_capture.proposals VALIDATE CONSTRAINT proposals_kind");
    const validated = await capture();
    assert.equal(validated.schema.constraints.find(x=>x.name==="proposals_kind").validated,undefined);
    const validationDiff = planMigration(unvalidated,validated);
    assert.equal(validationDiff.structure.length,1);
    assert.equal(validationDiff.structure[0].section,"constraints");
    assert.equal(planMigration(before,validated).structure.length,1);
  } finally {
    try { await client.query("ROLLBACK"); }
    finally { await client.end(); }
  }
});
