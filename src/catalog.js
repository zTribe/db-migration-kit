import { quoteIdentifier } from "./identifiers.js";

export const SECURITY_CATALOG_SQL = `
WITH app_tables AS (
  SELECT c.oid, n.nspname AS schema_name, c.relname, c.relkind, c.relrowsecurity, c.relforcerowsecurity,
         owner_role.rolname AS owner_name
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=c.relowner
  WHERE n.nspname = ANY($1::text[]) AND c.relkind IN ('r','p')
),
functions AS (
  SELECT p.oid, n.nspname AS schema_name, p.proname,
         pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_args,
         p.prosecdef AS security_definer, p.proconfig,
         owner_role.rolname AS owner_name,
         EXISTS (
           SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
           WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
         ) AS public_execute
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=p.proowner
  WHERE n.nspname = ANY($1::text[]) AND p.prokind='f'
)
SELECT
  coalesce((SELECT jsonb_agg(to_jsonb(t)) FROM app_tables t),'[]'::jsonb) AS tables,
  coalesce((SELECT jsonb_agg(to_jsonb(f)) FROM functions f),'[]'::jsonb) AS functions
`;

const TABLE_PRIVILEGES = ["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER"];
const SCHEMA_PRIVILEGES = ["USAGE","CREATE"];

/** Collect database facts on ONE connection and ONE read-only snapshot. No policies evaluated here. */
export async function collectSecurityCatalog(pool, rules = {}) {
  const schemas = rules.schemas ?? ["app"];
  if (!Array.isArray(schemas) || !schemas.length) throw new Error("security.schemas must be nonempty");
  for (const name of schemas) quoteIdentifier(name);
  const roles = [...new Set([
    ...(rules.requiredRoles ?? []), ...(rules.forbidBypassRlsRoles ?? []),
    ...(rules.forbidSuperuserRoles ?? []), ...(rules.deniedExecuteRoles ?? []),
    ...(rules.deniedTableDmlRoles ?? []), ...(rules.deniedTableSelectRoles ?? []),
    ...(rules.deniedSchemaUsageRoles ?? []), ...(rules.deniedSchemaCreateRoles ?? []),
    ...Object.keys(rules.allowedSchemaPrivileges ?? {}),
    ...Object.keys(rules.allowedTablePrivileges ?? {}),
  ])];
  const client = await pool.connect();
  let active = false;
  try {
    await client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
    active = true;
    await client.query("SET LOCAL statement_timeout='10s'");
    const {rows} = await client.query(SECURITY_CATALOG_SQL, [schemas]);
    const base = rows[0];
    const roleRows = roles.length ? (await client.query(
      "SELECT rolname, rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = ANY($1::text[])",
      [roles],
    )).rows : [];
    const known = new Set(roleRows.map(r => r.rolname));
    const privileges = {schemas: {}, tables: {}, functions: {}};
    // Resolve effective permissions once. Unknown roles stay absent and fail the policy gate.
    for (const role of roles.filter(name => known.has(name))) {
      privileges.schemas[role] = {};
      privileges.tables[role] = {};
      privileges.functions[role] = {};
      for (const schema of schemas) {
        const result = await client.query(
          "SELECT pg_catalog.has_schema_privilege($1,$2,'USAGE') AS usage, pg_catalog.has_schema_privilege($1,$2,'CREATE') AS create_allowed",
          [role,schema],
        );
        privileges.schemas[role][schema] = {USAGE:result.rows[0].usage, CREATE:result.rows[0].create_allowed};
      }
      for (const table of base.tables) {
        const key = `${table.schema_name}.${table.relname}`;
        const qualified = `${quoteIdentifier(table.schema_name)}.${quoteIdentifier(table.relname)}`;
        const result = await client.query(
          `SELECT ${TABLE_PRIVILEGES.map((p,i) => `pg_catalog.has_table_privilege($1,$2,'${p}') AS p${i}`).join(", ")}`,
          [role, qualified],
        );
        privileges.tables[role][key] = Object.fromEntries(TABLE_PRIVILEGES.map((p,i) => [p,result.rows[0][`p${i}`]]));
      }
      for (const fn of base.functions) {
        const key = `${fn.schema_name}.${fn.proname}(${fn.identity_args})`;
        const result = await client.query("SELECT pg_catalog.has_function_privilege($1,$2,'EXECUTE') AS allowed", [role,fn.oid]);
        privileges.functions[role][key] = {EXECUTE:result.rows[0].allowed};
      }
    }
    await client.query("COMMIT");
    active = false;
    return {tables:base.tables,functions:base.functions,roles:roleRows,privileges,schemas};
  } catch (error) {
    if (active) await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {client.release();}
}
