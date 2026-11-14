import { assertMigrationReview, planMigration } from "./migration-plan.js";
import { readPermissionState } from "./permission-state.js";
import { readSchemaCatalogOnClient } from "./schema-audit.js";

export async function readTargetState(client, schemas, includeStructure = true) {
  return {
    version: 1,
    schema: includeStructure ? await readSchemaCatalogOnClient(client, schemas) : null,
    permissions: await readPermissionState(client, schemas),
  };
}

export function guardMigration(version, before, after, review) {
  const plan = planMigration(before, after);
  assertMigrationReview(plan, review);
  const schemas = before.permissions.schemas.map(row => row.schema).sort();
  if (!schemas.length || JSON.stringify(schemas) !== JSON.stringify(after.permissions.schemas.map(row => row.schema).sort())) {
    throw new Error("Guarded migration requires stable, nonempty schema coverage");
  }
  async function verify(client, expected, stage) {
    const actual = await readTargetState(client, schemas, expected.schema !== null);
    for (const section of ["databasePrivileges", "defaultPrivileges"]) {
      if (expected.permissions[section] === undefined) delete actual.permissions[section];
    }
    const diff = planMigration(actual, expected);
    if (diff.changes.length || diff.structure.length) {
      throw new Error(`Migration ${version} ${stage} differs from reviewed state (${diff.digest})`);
    }
  }
  return {
    version,
    before: client => verify(client, before, "precondition"),
    after: client => verify(client, after, "result"),
  };
}
