import test from "node:test";
import assert from "node:assert/strict";
import { planMigration, generateMigrationSql } from "../src/index.js";

test("permission changes require review of the exact plan before SQL generation", () => {
  const before = { version: 1, schema: null, permissions: {
    schemas: [{ schema: "app", owner: "postgres", acl: "{postgres=UC/postgres}" }],
    objects: [{ schema: "app", name: "m", kind: "r", owner: "postgres", rls: false, force_rls: false, acl: null }],
    columnPrivileges: [], functions: [], policies: [], roles: [], memberships: [],
  } };
  const after = structuredClone(before);
  after.permissions.schemas[0].acl = "{postgres=UC/postgres,reader=U/postgres}";
  after.permissions.objects[0].rls = true;
  const plan = planMigration(before, after);
  assert.throws(() => generateMigrationSql(before, after), /review required/);
  const review = { digest: plan.digest, reason: "Enable RLS and allow schema lookup" };
  assert.equal(generateMigrationSql(before, after, review),
    'GRANT USAGE ON SCHEMA "app" TO "reader";\nALTER TABLE "app"."m" ENABLE ROW LEVEL SECURITY;');
  after.permissions.objects[0].force_rls = true;
  assert.throws(() => generateMigrationSql(before, after, review), /review required/);
  after.permissions.memberships.push({ member: "reader", parent: "postgres" });
  assert.throws(() => generateMigrationSql(before, after, {
    digest: planMigration(before, after).digest, reason: "Review role change",
  }), /explicit SQL/);
});
