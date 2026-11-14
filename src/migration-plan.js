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
  databasePrivileges: ["scope"],
  defaultPrivileges: ["owner", "schema", "kind"],
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
    if (!row || fields.some(field => typeof row[field] !== "string" || (!row[field] && field !== "arguments" && !(section === "defaultPrivileges" && field === "schema")))) {
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
    if (["databasePrivileges", "defaultPrivileges"].includes(section) && before?.[section] === undefined && after?.[section] === undefined) return [];
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

const scalarTypes = new Set(["integer", "bigint", "text", "boolean", "uuid", "jsonb", "timestamp with time zone"]);

function renderStructure(change, after) {
  if (change.section !== "columns" || change.code !== "UNEXPECTED") return null;
  const matches = after.columns.filter(row => `${row.schema_name}.${row.table_name}.${row.name}` === change.key);
  if (matches.length !== 1) return null;
  const row = matches[0];
  if (!scalarTypes.has(row.type) || row.not_null !== false || row.default_expr !== null || row.identity !== "" || row.generated !== "") return null;
  return `ALTER TABLE ${quote(row.schema_name)}.${quote(row.table_name)} ADD COLUMN ${quote(row.name)} ${row.type};`;
}

export function planMigration(before, after) {
  if (before?.version !== 1 || after?.version !== 1) throw new Error("Expected target state version 1");
  if ((before.schema === null) !== (after.schema === null)) throw new Error("Both states must use the same schema coverage");
  const permissions = diffPermissions(before.permissions, after.permissions);
  const structure = before.schema === null ? [] :
    compareSchemaCatalog(normalizeSchemaCatalog(canonical(before.schema)), normalizeSchemaCatalog(canonical(after.schema)))
      .differences.map(change => ({ ...change, sql: renderStructure(change, after.schema) }));
  const changes = permissions.map(change => ({ ...change, sql: render(change) }));
  const manual = [...structure, ...changes].some(change => !change.sql);
  const digest = checksumText(JSON.stringify(canonical({ changes, structure, schemaBefore: before.schema, schemaAfter: after.schema })));
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
  return [...plan.structure, ...plan.changes].map(change => change.sql).join("\n");
}
