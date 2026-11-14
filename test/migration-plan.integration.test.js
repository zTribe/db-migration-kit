import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { generateMigrationSql, planMigration } from "../src/index.js";

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
