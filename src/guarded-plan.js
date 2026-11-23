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


// Portable reviews are captured with a disposable migrator. Some historical
// ACL grantors may differ when the real login is also a pre-existing role
// (for example postgres). Compare the *change* to a function ACL, not the
// unrelated, unchanged historical ACL entries. Complex ACL syntax fails
// closed rather than using lossy string heuristics.
function simpleAclEntries(value) {
  if (typeof value !== "string" || !/^\{[^{}"\\]*\}$/.test(value)) return null;
  const items=value.slice(1,-1).split(",").filter(Boolean);
  if(items.some(x=>!/^[^=,{}"\\]+=[A-Za-z*]*\/[^=,{}"\\]+$/.test(x)))return null;
  if(new Set(items).size!==items.length)return null;
  return new Set(items);
}

function aclDelta(previous, desired) {
  const before=simpleAclEntries(previous);
  const after=simpleAclEntries(desired);
  if(!before||!after)return null;
  return {
    added:[...after].filter(x=>!before.has(x)).sort(),
    removed:[...before].filter(x=>!after.has(x)).sort(),
  };
}

function portableChangeMatches(expected, observed) {
  if (JSON.stringify(expected)===JSON.stringify(observed)) return true;
  if(expected?.section!=="functions" || observed?.section!=="functions" ||
     !expected.previous || !expected.desired || !observed.previous || !observed.desired ||
     JSON.stringify(expected.identity)!==JSON.stringify(observed.identity) ||
     expected.sql!==observed.sql) return false;
  const stripAcl=({acl,...row})=>row;
  if(JSON.stringify(stripAcl(expected.previous))!==JSON.stringify(stripAcl(expected.desired)) ||
     JSON.stringify(stripAcl(observed.previous))!==JSON.stringify(stripAcl(observed.desired)) ||
     JSON.stringify(stripAcl(expected.previous))!==JSON.stringify(stripAcl(observed.previous)))
    return false;
  const planned=aclDelta(expected.previous.acl,expected.desired.acl);
  const actual=aclDelta(observed.previous.acl,observed.desired.acl);
  return Boolean(planned && actual && JSON.stringify(planned)===JSON.stringify(actual));
}

export function portableReviewDeltaMatches(expected, observed) {
  if(expected.changes.length!==observed.changes.length ||
     expected.structure.length!==observed.structure.length) return false;
  if(JSON.stringify(expected.structure)!==JSON.stringify(observed.structure))return false;
  return expected.changes.every((change,index)=>
    portableChangeMatches(change,observed.changes[index]));
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
        if (!portableReviewDeltaMatches(deltas(plan), deltas(observed))) fail("result", observed);
      } else {
        const diff = planMigration(actual, after);
        if (diff.changes.length || diff.structure.length) fail("result", diff);
      }
    },
  };
}
