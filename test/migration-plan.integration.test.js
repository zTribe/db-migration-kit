import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { generateMigrationSql, planMigration, readTargetState } from "../src/index.js";

test("PG17 executes reviewed RLS and ACL SQL", { skip: !process.env.PG_TEST_URL }, async () => {
  const client = new pg.Client({ connectionString: process.env.PG_TEST_URL });
  await client.connect();
  try {
    await client.query("BEGIN");
    await client.query("CREATE SCHEMA kit_plan_test; CREATE TABLE kit_plan_test.messages (id integer)");
    const before = {
      version: 1, schema: null, permissions: {
        schemas: [{ schema: "kit_plan_test", owner: "postgres", acl: "{postgres=UC/postgres}" }],
        objects: [{ schema: "kit_plan_test", name: "messages", kind: "r", owner: "postgres", rls: false, force_rls: false, acl: null }],
        columnPrivileges: [], functions: [], policies: [], roles: [], memberships: [],
      },
    };
    const after = structuredClone(before);
    after.permissions.schemas[0].acl = "{postgres=UC/postgres,=U/postgres}";
    after.permissions.objects[0].rls = true;
    const { digest } = planMigration(before, after);
    await client.query(generateMigrationSql(before, after, { digest, reason: "Isolated regression test" }));
    const { rows } = await client.query(`SELECT
      current_setting('server_version_num')::int / 10000 AS major,
      EXISTS (SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) a WHERE n.nspname = 'kit_plan_test' AND a.grantee = 0 AND a.privilege_type = 'USAGE') AS usage,
      relrowsecurity AS rls FROM pg_class WHERE oid = 'kit_plan_test.messages'::regclass`);
    assert.deepEqual(rows, [{ major: 17, usage: true, rls: true }]);
    const reverse = planMigration(after, before);
    await client.query(generateMigrationSql(after, before, { digest: reverse.digest, reason: "Verify revoke" }));
    const result = await client.query("SELECT EXISTS (SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) a WHERE n.nspname = 'kit_plan_test' AND a.grantee = 0 AND a.privilege_type = 'USAGE') AS usage");
    assert.equal(result.rows[0].usage, false);
  } finally {
    await client.query("ROLLBACK").finally(() => client.end());
  }
});

test("PG17 generates and replays a nullable smallint column from real catalogs", { skip: !process.env.PG_TEST_URL }, async () => {
  const client = new pg.Client({ connectionString: process.env.PG_TEST_URL });
  await client.connect();
  try {
    await client.query("BEGIN");
    await client.query("CREATE SCHEMA kit_smallint_test; CREATE TABLE kit_smallint_test.proposals (id integer)");
    const schemas = ["kit_smallint_test"];
    const before = await readTargetState(client, schemas);
    await client.query("SAVEPOINT before_candidate");
    await client.query("ALTER TABLE kit_smallint_test.proposals ADD COLUMN vote_state smallint");
    const after = await readTargetState(client, schemas);
    await client.query("ROLLBACK TO SAVEPOINT before_candidate");
    const plan = planMigration(before, after);
    assert.equal(plan.manual, false);
    const sql = generateMigrationSql(before, after, { digest: plan.digest, reason: "Add nullable vote state" });
    assert.equal(sql, 'ALTER TABLE "kit_smallint_test"."proposals" ADD COLUMN "vote_state" smallint;');
    await client.query(sql);
    assert.deepEqual(await readTargetState(client, schemas), after);

    await client.query("ALTER TABLE kit_smallint_test.proposals ALTER COLUMN vote_state SET DEFAULT 0");
    const withDefault = await readTargetState(client, schemas);
    const { digest } = planMigration(before, withDefault);
    assert.throws(
      () => generateMigrationSql(before, withDefault, { digest, reason: "Check unsupported column defaults" }),
      /columns: "kit_smallint_test.proposals.vote_state".*without defaults/,
    );
  } finally {
    await client.query("ROLLBACK").finally(() => client.end());
  }
});
