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
      // Function ACLs support EXECUTE only. Reject unknown privilege letters,
      // repeated grants, and malformed option chains instead of merging them.
      if (privilege !== "X") return null;
      const grantOption = flags[i + 1] === "*";
      if (grantOption) i++;
      const key = JSON.stringify([grantee, grantor, privilege]);
      if (grants.has(key)) return null;
      const effectiveOption = grantOption && !(grantee === owner && grantor === owner);
      grants.set(key, effectiveOption);
    }
  }
  return [...grants].sort(([a], [b]) => a.localeCompare(b));
}

// Reject collisions between a reviewed historical role and the portable
// migrator alias. A name collision cannot prove those distinct identities
// have the same Owner or GRANT provenance in the target environment.
function hasAmbiguousMigratorAlias(row, actualRole) {
  if (typeof actualRole !== "string" || !actualRole || actualRole === MIGRATION_ROLE) return true;
  if (typeof row?.acl !== "string") return false;
  const items=row.acl.slice(1,-1).split(",").filter(Boolean);
  const hasRole=name=>items.some(item=>{
    const parts=item.split("/");
    const grantee=parts[0]?.split("=")[0];
    return grantee===name || parts[1]===name;
  });
  // Historical owner and the disposable migrator can both be recorded in
  // a reviewed ACL. They may collapse to ONE principal only if the real
  // deployment login is that historical function owner. The complete ACL
  // still has to match after canonicalization; extra or missing grants fail.
  return hasRole(actualRole) && hasRole(MIGRATION_ROLE) && row.owner !== actualRole;
}

function portableReviewedObjectMatches(expected, actual, role, section) {
  if (JSON.stringify(expected)===JSON.stringify(actual)) return true;
  if (section!=="functions" || !expected || !actual ||
      hasAmbiguousMigratorAlias(expected,role)) return false;
  const omitAcl=({acl,...rest})=>({
    ...rest,owner:rest.owner===role?MIGRATION_ROLE:rest.owner
  });
  if(JSON.stringify(omitAcl(expected))!==JSON.stringify(omitAcl(actual)))return false;
  const beforeAcl=canonicalFunctionAcl(expected.acl,role,MIGRATION_ROLE);
  const actualAcl=canonicalFunctionAcl(actual.acl,role,MIGRATION_ROLE);
  return Boolean(beforeAcl&&actualAcl&&JSON.stringify(beforeAcl)===JSON.stringify(actualAcl));
}

// A delta-only check misses privileges already present before the upgrade.
// Verify the reviewed precondition of each changed object before applying SQL.
export function portablePreconditionMatches(reviewed, actual, changes, role) {
  const keys={
    schemas:["schema"],objects:["schema","name"],
    columnPrivileges:["schema","relation","column_name"],
    functions:["schema","name","arguments"],
    policies:["schema","tablename","policyname"],
    roles:["rolname"],memberships:["member","parent"],
    databasePrivileges:["scope"],defaultPrivileges:["owner","schema","kind"]
  };
  for(const change of changes){
    const fields=keys[change.section];
    if(!fields)return false;
    const find=(state)=>{
      const rows=state.permissions[change.section]??[];
      const matches=rows.filter(row=>JSON.stringify(fields.map(k=>row[k]))===JSON.stringify(change.identity));
      return matches.length===1?matches[0]:matches.length===0?null:undefined;
    };
    const expected=find(reviewed),observed=find(actual);
    if(expected===undefined || observed===undefined ||
       !portableReviewedObjectMatches(expected,observed,role,change.section))
      return false;
  }
  return true;
}

function portableChangeMatches(expected, observed, actualRole) {
  if (JSON.stringify(expected) === JSON.stringify(observed)) return true;
  if (hasAmbiguousMigratorAlias(expected?.previous,actualRole) ||
      hasAmbiguousMigratorAlias(expected?.desired,actualRole)) return false;
  if (expected?.section !== "functions" || observed?.section !== "functions" ||
      !expected.previous || !expected.desired || !observed.previous || !observed.desired ||
      JSON.stringify(expected.identity) !== JSON.stringify(observed.identity) ||
      expected.sql !== observed.sql) return false;
  // The reviewed function can be owned by a historical role (postgres)
  // that is also the actual Production migrator. Normalization in the live
  // capture replaces that owner's name with @migration-role; compare the
  // same real identity rather than mistaking the rename for owner drift.
  const stripAcl = ({ acl, ...row }) => ({
    ...row, owner: row.owner === actualRole ? MIGRATION_ROLE : row.owner
  });
  for (const field of ["previous", "desired"]) {
    if (JSON.stringify(stripAcl(expected[field])) !== JSON.stringify(stripAcl(observed[field])))
      return false;
    if (stripAcl(expected[field]).owner !== MIGRATION_ROLE) return false;
    // Different reviewed owner names may only map together when the
    // actual migrator IS the historical owner, never merely a grantee.
    const planned=canonicalFunctionAcl(expected[field].acl,actualRole,MIGRATION_ROLE);
    const actual=canonicalFunctionAcl(observed[field].acl,actualRole,MIGRATION_ROLE);
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
      if (portable) {
        const {rows:[identity]}=await client.query("SELECT current_user AS role");
        if(!portablePreconditionMatches(before,actual,plan.changes,identity.role))
          fail("precondition",planMigration(actual,before));
        initialStates.set(client,actual);
      } else {
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


// Kit Lite: compare the ACTUAL security changes made in one PostgreSQL
// transaction against reviewed change *intent*. Never compare cross-environment
// before snapshots or infer historic grantor/owner identity equivalence.
// The SQL checksum and reviewed plan digest are independently verified by
// loadMigrationConfig. Owner/capability checks remain in the shared Runner.
function aclEntitlements(value, reviewRole = null) {
  if (value == null) return new Set();
  if (typeof value !== "string" || !/^\{[^{}"\\]*\}$/.test(value))
    throw Error("Contract review cannot parse ACL; strict manual review required");
  const result=new Set();
  for (const entry of value.slice(1,-1).split(",").filter(Boolean)) {
    const parsed=/^([^=,{}"\\]*)=([A-Za-z*]*)\/([^=,{}"\\]+)$/.exec(entry);
    if (!parsed) throw Error("Contract review rejects unsupported ACL");
    const [,role,flags]=parsed;
    if (!flags || /^\*/.test(flags)) throw Error("Contract review rejects malformed ACL");
    for (let i=0;i<flags.length;i++) {
      const privilege=flags[i];
      if (!/[A-Za-z]/.test(privilege)) throw Error("Contract review rejects ACL privilege");
      const option=flags[i+1]==="*";
      if (option) i++;
      const recipient=reviewRole && role===MIGRATION_ROLE ? reviewRole : role;
      const key=JSON.stringify([recipient,privilege,option]);
      if(result.has(key)) throw Error("Contract review rejects ambiguous ACL grants");
      result.add(key);
    }
  }
  return result;
}
function entitlementDelta(previous,desired,reviewRole=null) {
  const from=aclEntitlements(previous,reviewRole),to=aclEntitlements(desired,reviewRole);
  return {
    added:[...to].filter(x=>!from.has(x)).sort(),
    removed:[...from].filter(x=>!to.has(x)).sort()
  };
}
function reviewedScope(change) {
  return JSON.stringify([change.section,change.identity]);
}
function structuralScope(change) {
  return JSON.stringify([change.section,change.key,change.code]);
}
export function contractChangeMatches(reviewed,observed,actualRole) {
  if (!reviewed || !observed || reviewedScope(reviewed)!==reviewedScope(observed))
    return false;
  const expected=reviewed.desired,actual=observed.desired;
  if (Boolean(expected)!==Boolean(actual)) return false;
  if (!expected) return true;
  // Validate final runtime security properties, not historical ACL grantors.
  const {acl:expectedAcl,owner:expectedOwner,...otherExpected}=expected;
  const {acl:actualAcl,owner:actualOwner,...otherActual}=actual;
  // Only the literal reviewed migration-role placeholder is substituted;
  // historical postgres, other owners and ACL grantors are never inferred.
  const replacePlaceholder=value=>Array.isArray(value)
    ? value.map(replacePlaceholder)
    : value && typeof value==="object"
      ? Object.fromEntries(Object.entries(value).map(([k,v])=>[k,replacePlaceholder(v)]))
      : value===MIGRATION_ROLE ? actualRole : value;
  if(JSON.stringify(replacePlaceholder(otherExpected))!==JSON.stringify(otherActual)) return false;
  if (expectedOwner !== MIGRATION_ROLE && expectedOwner !== actualOwner) return false;
  if (expectedOwner === MIGRATION_ROLE && actualOwner !== actualRole) return false;
  const expectedDelta=entitlementDelta(reviewed.previous?.acl,expectedAcl,actualRole);
  const actualDelta=entitlementDelta(observed.previous?.acl,actualAcl);
  return JSON.stringify(expectedDelta)===JSON.stringify(actualDelta);
}

/**
 * One execution path for every migration: reviewed SQL/checksum, real owner
 * capability preflight, transaction, and live catalog security-delta checks.
 * No portable role alias or historic ACL grantor equivalence inference.
 * Business-specific behavior, RLS authorization and owner assertions remain
 * the responsibility of each project's real PG17 migration contracts.
 */
export function contractMigration(version,before,after,review) {
  const expected=planMigration(before,after);
  assertMigrationReview(expected,review);
  if (before.migrationRole!==after.migrationRole) throw Error("Migration role coverage differs");
  const schemas=before.permissions.schemas.map(x=>x.schema).sort();
  if (!schemas.length ||
      JSON.stringify(schemas)!==JSON.stringify(after.permissions.schemas.map(x=>x.schema).sort()))
    throw Error("Contract requires stable nonempty schema coverage");
  const started=new WeakMap();
  return {
    version,
    async before(client) {
      // The local state is the authority. Do not compare it to a disposable
      // fixture's historical grantors, or merge two distinct principals.
      const state=await readTargetState(client,schemas,before.schema!==null);
      started.set(client,state);
    },
    async after(client) {
      const initial=started.get(client);
      started.delete(client);
      if (!initial) throw Error("Contract is missing its transaction-local before state");
      const actual=await readTargetState(client,schemas,after.schema!==null);
      const observed=planMigration(initial,actual);
      const expectedChanges=new Map(expected.changes.map(x=>[reviewedScope(x),x]));
      const observedChanges=new Map(observed.changes.map(x=>[reviewedScope(x),x]));
      // Unexpected privileges, owner changes, RLS toggles, policies and
      // schema changes must NEVER silently pass just because SQL executed.
      if (expectedChanges.size!==observedChanges.size ||
          expected.structure.length!==observed.structure.length)
        throw Error("Migration "+version+" contract changed unexpected catalog objects");
      const {rows:[identity]}=await client.query("SELECT current_user AS role");
      for (const [key,change] of expectedChanges)
        if (!contractChangeMatches(change,observedChanges.get(key),identity.role))
          throw Error("Migration "+version+" contract changed unexpected grants, owner or security properties: "+key);
      const expectedStructure=expected.structure.map(structuralScope).sort();
      const observedStructure=observed.structure.map(structuralScope).sort();
      if(JSON.stringify(expectedStructure)!==JSON.stringify(observedStructure))
        throw Error("Migration "+version+" contract structural change differs from review");
    }
  };
}
