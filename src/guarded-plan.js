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


// Portable reviews may have a disposable migrator distinct from the real
// login. In Production the real login can be the historical ACL grantor itself.
// Compare full before AND after function ACLs, mapping only that proven login
// to @migration-role. Unrelated roles, grantors, privileges and changes remain
// strict. Unsupported ACL syntax fails closed.
function canonicalFunctionAcl(value, actualRole, owner) {
  if (typeof value !== "string" || !/^\{[^{}"\\]*\}$/.test(value) ||
      typeof actualRole !== "string" || !actualRole || actualRole === MIGRATION_ROLE)
    return null;
  const entries = value.slice(1, -1).split(",").filter(Boolean);
  const grants = new Map();
  for (const entry of entries) {
    const match = /^([^=,{}"\\]*)=([A-Za-z*]*)\/([^=,{}"\\]+)$/.exec(entry);
    if (!match) return null;
    const [, rawGrantee, flags, rawGrantor] = match;
    const map = name => name === actualRole ? MIGRATION_ROLE : name;
    const grantee = map(rawGrantee);
    const grantor = map(rawGrantor);
    if (/^\*/.test(flags)) return null;
    for (let i = 0; i < flags.length; i++) {
      const privilege = flags[i];
      if (privilege === "*") return null;
      const grantOption = flags[i + 1] === "*";
      if (grantOption) i++;
      const key = JSON.stringify([grantee, grantor, privilege]);
      const effectiveOption = grantOption && !(grantee === owner && grantor === owner);
      grants.set(key, grants.get(key) === true || effectiveOption);
    }
  }
  return [...grants].sort(([a], [b]) => a.localeCompare(b));
}

function portableChangeMatches(expected, observed, actualRole) {
  if (JSON.stringify(expected) === JSON.stringify(observed)) return true;
  if (expected?.section !== "functions" || observed?.section !== "functions" ||
      !expected.previous || !expected.desired || !observed.previous || !observed.desired ||
      JSON.stringify(expected.identity) !== JSON.stringify(observed.identity) ||
      expected.sql !== observed.sql) return false;
  const stripAcl = ({ acl, ...row }) => row;
  for (const field of ["previous", "desired"]) {
    if (JSON.stringify(stripAcl(expected[field])) !== JSON.stringify(stripAcl(observed[field])))
      return false;
    const owner=expected[field].owner;
    if (owner !== MIGRATION_ROLE) return false;
    const planned=canonicalFunctionAcl(expected[field].acl,actualRole,owner);
    const actual=canonicalFunctionAcl(observed[field].acl,actualRole,owner);
    if (!planned || !actual || JSON.stringify(planned) !== JSON.stringify(actual))
      return false;
  }
  return true;
}

export function portableReviewDeltaMatches(expected, observed, actualRole) {
  if (expected.changes.length !== observed.changes.length ||
      expected.structure.length !== observed.structure.length) return false;
  if (JSON.stringify(expected.structure) !== JSON.stringify(observed.structure)) return false;
  return expected.changes.every((change, index) =>
    portableChangeMatches(change, observed.changes[index], actualRole));
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
        const { rows: [identity] } = await client.query("SELECT current_user AS role");
        if (!portableReviewDeltaMatches(deltas(plan), deltas(observed), identity.role)) fail("result", observed);
      } else {
        const diff = planMigration(actual, after);
        if (diff.changes.length || diff.structure.length) fail("result", diff);
      }
    },
  };
}
