import { renderAcl } from "./acl-plan.js";
import { checksumText } from "./checksum.js";
import { normalizeSchemaCatalog, compareSchemaCatalog } from "./schema-audit.js";

const keys = {
  schemas: ["schema"],
  objects: ["schema", "name"],
  columnPrivileges: ["schema", "relation", "column_name"],
  functions: ["schema", "name", "arguments"],
  policies: ["schema", "tablename", "policyname"],
  roles: ["rolname"],
  memberships: ["member", "parent"],
};

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
}

function indexRows(rows, fields, section) {
  if (!Array.isArray(rows)) throw new Error(`Missing permissions section: ${section}`);
  const index = new Map();
  for (const row of rows) {
    if (!row || fields.some(field => typeof row[field] !== "string" || (!row[field] && field !== "arguments"))) {
      throw new Error(`Invalid identity in permissions section: ${section}`);
    }
    const key = JSON.stringify(fields.map(field => row[field]));
    if (index.has(key)) throw new Error(`Duplicate permission identity in ${section}: ${key}`);
    index.set(key, canonical(row));
  }
  return index;
}

export function diffPermissions(before, after) {
  return Object.entries(keys).flatMap(([section, fields]) => {
    const from = indexRows(before?.[section], fields, section);
    const to = indexRows(after?.[section], fields, section);
    return [...new Set([...from.keys(), ...to.keys()])].sort().flatMap(key => {
      const previous = from.get(key) ?? null;
      const desired = to.get(key) ?? null;
      return JSON.stringify(previous) === JSON.stringify(desired) ? [] :
        [{ section, identity: JSON.parse(key), previous, desired }];
    });
  });
}

const quote = value => '"' + value.replaceAll('"', '""') + '"';

function render(change) {
  const { section, previous, desired } = change;
  const acl = renderAcl(change, quote);
  if (acl) return acl;
  if (section !== "objects" || !previous || !desired || !["r", "p"].includes(previous.kind)) return null;
  const { rls, force_rls, ...rest } = desired;
  const { rls: oldRls, force_rls: oldForce, ...oldRest } = previous;
  if ([rls, force_rls, oldRls, oldForce].some(value => typeof value !== "boolean") ||
      JSON.stringify(rest) !== JSON.stringify(oldRest)) return null;
  const table = change.identity.map(quote).join(".");
  return [
    rls === oldRls ? null : `ALTER TABLE ${table} ${rls ? "ENABLE" : "DISABLE"} ROW LEVEL SECURITY;`,
    force_rls === oldForce ? null : `ALTER TABLE ${table} ${force_rls ? "FORCE" : "NO FORCE"} ROW LEVEL SECURITY;`,
  ].filter(Boolean).join("\n");
}

export function planMigration(before, after) {
  if (before?.version !== 1 || after?.version !== 1) throw new Error("Expected target state version 1");
  if ((before.schema === null) !== (after.schema === null)) throw new Error("Both states must use the same schema coverage");
  const permissions = diffPermissions(before.permissions, after.permissions);
  const structure = before.schema === null ? [] :
    compareSchemaCatalog(normalizeSchemaCatalog(before.schema), normalizeSchemaCatalog(after.schema)).differences;
  const changes = permissions.map(change => ({ ...change, sql: render(change) }));
  const manual = structure.length > 0 || changes.some(change => !change.sql);
  const digest = checksumText(JSON.stringify(canonical({ changes, structure })));
  return { changes, structure, manual, digest };
}

export function assertMigrationReview(plan, review) {
  if (!plan.changes.length && !plan.structure.length) return;
  if (review?.digest !== plan.digest || typeof review.reason !== "string" || !review.reason.trim()) {
    throw new Error(`Migration review required for digest ${plan.digest}`);
  }
}

export function generateMigrationSql(before, after, review) {
  const plan = planMigration(before, after);
  assertMigrationReview(plan, review);
  if (plan.manual) throw new Error("Plan contains changes requiring explicit SQL");
  return plan.changes.map(change => change.sql).join("\n");
}
