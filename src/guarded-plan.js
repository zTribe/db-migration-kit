import { MIGRATION_ROLE, normalizeMigrationRole } from "./migration-role.js";
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
  if (before.migrationRole !== after.migrationRole) throw new Error("Migration role coverage differs");
  const schemas = before.permissions.schemas.map(row => row.schema).sort();
  if (!schemas.length || JSON.stringify(schemas) !== JSON.stringify(after.permissions.schemas.map(row => row.schema).sort())) {
    throw new Error("Guarded migration requires stable, nonempty schema coverage");
  }
  const portable = before.migrationRole === MIGRATION_ROLE;
  const initialStates = new WeakMap();
  async function capture(client, expected) {
    let actual = await readTargetState(client, schemas, expected.schema !== null);
    if (portable) {
      const { rows: [identity] } = await client.query("SELECT current_user AS role");
      actual = normalizeMigrationRole(actual, identity.role);
    }
    for (const section of ["databasePrivileges", "defaultPrivileges"]) {
      if (expected.permissions[section] === undefined) delete actual.permissions[section];
    }
    return actual;
  }
  const deltas = ({ changes, structure }) => ({ changes, structure });
  function fail(stage, diff) {
    throw new Error(`Migration ${version} ${stage} differs from reviewed state (${diff.digest})`);
  }
  return {
    version,
    async before(client) {
      const actual = await capture(client, before);
      if (portable) initialStates.set(client, actual);
      else {
        const diff = planMigration(actual, before);
        if (diff.changes.length || diff.structure.length) fail("precondition", diff);
      }
    },
    async after(client) {
      const actual = await capture(client, after);
      if (portable) {
        const initial = initialStates.get(client);
        initialStates.delete(client);
        if (!initial) throw new Error("Missing migration precondition capture");
        const observed = planMigration(initial, actual);
        if (JSON.stringify(deltas(observed)) !== JSON.stringify(deltas(plan))) fail("result", observed);
      } else {
        const diff = planMigration(actual, after);
        if (diff.changes.length || diff.structure.length) fail("result", diff);
      }
    },
  };
}
