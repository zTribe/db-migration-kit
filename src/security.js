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

export async function inspectRuntimeSecurity(pool, rules) {
  const schemas = rules.schemas ?? ["app"];
  for (const schema of schemas) quoteIdentifier(schema);
  const { rows } = await pool.query(SECURITY_CATALOG_SQL, [schemas]);
  const snapshot = rows[0];
  const failures = [];
  const requiredRls = new Set(rules.requireRlsOn ?? []);
  const requiredForceRls = new Set(rules.requireForceRlsOn ?? []);
  for (const table of snapshot.tables) {
    const key = `${table.schema_name}.${table.relname}`;
    if (requiredRls.has(key) && !table.relrowsecurity) failures.push(`${key}: RLS is disabled`);
    if (requiredForceRls.has(key) && !table.relforcerowsecurity) failures.push(`${key}: FORCE RLS is disabled`);
  }
  const allowedOwners = new Set(rules.allowedDefinerOwners ?? []);
  for (const fn of snapshot.functions) {
    if (!fn.security_definer) continue;
    const label = `${fn.schema_name}.${fn.proname}(${fn.identity_args})`;
    if (!allowedOwners.has(fn.owner_name)) failures.push(`${label}: unexpected SECURITY DEFINER owner ${fn.owner_name}`);
    const settings = fn.proconfig ?? [];
    const searchPath = settings.find(value => value.startsWith("search_path="));
    if (rules.requireFixedSearchPath !== false && !searchPath) failures.push(`${label}: SECURITY DEFINER has no fixed search_path`);
    if (searchPath && /(^|[, ])public([, ]|$)|\$user/i.test(searchPath)) failures.push(`${label}: unsafe search_path ${searchPath}`);
    if (fn.public_execute) failures.push(`${label}: PUBLIC can EXECUTE`);
    for (const role of rules.deniedExecuteRoles ?? []) {
      const result = await pool.query("SELECT pg_catalog.has_function_privilege($1,$2,'EXECUTE') AS allowed", [role, fn.oid]);
      if (result.rows[0]?.allowed) failures.push(`${label}: ${role} can EXECUTE`);
    }
  }
  for (const role of rules.deniedTableDmlRoles ?? []) {
    for (const table of snapshot.tables) {
      const key = `${table.schema_name}.${table.relname}`;
      const result = await pool.query(`
        SELECT
          pg_catalog.has_table_privilege($1,$2,'INSERT') AS ins,
          pg_catalog.has_table_privilege($1,$2,'UPDATE') AS upd,
          pg_catalog.has_table_privilege($1,$2,'DELETE') AS del,
          pg_catalog.has_table_privilege($1,$2,'TRUNCATE') AS trunc,
          pg_catalog.has_table_privilege($1,$2,'REFERENCES') AS refs,
          pg_catalog.has_table_privilege($1,$2,'TRIGGER') AS trig
      `, [role, `${quoteIdentifier(table.schema_name)}.${quoteIdentifier(table.relname)}`]);
      const grants = result.rows[0];
      for (const [privilege, field] of [["INSERT","ins"],["UPDATE","upd"],["DELETE","del"],["TRUNCATE","trunc"],["REFERENCES","refs"],["TRIGGER","trig"]]) {
        if (grants[field]) failures.push(`${role} has effective ${privilege} on ${key}`);
      }
    }
  }
  // Check effective schema privileges for runtime roles, including inherited grants.
  for (const role of rules.deniedSchemaUsageRoles ?? []) {
    for (const schema of schemas) {
      const result = await pool.query("SELECT pg_catalog.has_schema_privilege($1,$2,'USAGE') AS allowed", [role, schema]);
      if (result.rows[0]?.allowed) failures.push(`${role} has USAGE on schema ${schema}`);
    }
  }
  for (const role of rules.deniedTableSelectRoles ?? []) {
    for (const table of snapshot.tables) {
      const key = `${table.schema_name}.${table.relname}`;
      const result = await pool.query("SELECT pg_catalog.has_table_privilege($1,$2,'SELECT') AS allowed", [role, `${quoteIdentifier(table.schema_name)}.${quoteIdentifier(table.relname)}`]);
      if (result.rows[0]?.allowed) failures.push(`${role} has effective SELECT on ${key}`);
    }
  }
  for (const role of rules.deniedTableDmlRoles ?? []) {
    for (const table of snapshot.tables) {
      const key = `${table.schema_name}.${table.relname}`;
      const result = await pool.query("SELECT pg_catalog.has_table_privilege($1,$2,'SELECT') AS allowed", [role, `${quoteIdentifier(table.schema_name)}.${quoteIdentifier(table.relname)}`]);
      if (rules.denySelectForDmlRoles && result.rows[0]?.allowed) failures.push(`${role} has effective SELECT on ${key}`);
    }
  }
  for (const [role, privileges] of Object.entries(rules.allowedSchemaPrivileges ?? {})) {
    for (const schema of schemas) {
      for (const privilege of privileges) {
        const result = await pool.query("SELECT pg_catalog.has_schema_privilege($1,$2,$3) AS allowed", [role, schema, privilege]);
        if (!result.rows[0]?.allowed) failures.push(`${role} lacks ${privilege} on schema ${schema}`);
      }
    }
  }
  for (const [role, privileges] of Object.entries(rules.allowedTablePrivileges ?? {})) {
    for (const table of snapshot.tables) {
      const key = `${table.schema_name}.${table.relname}`;
      for (const privilege of privileges) {
        const result = await pool.query("SELECT pg_catalog.has_table_privilege($1,$2,$3) AS allowed", [role, `${quoteIdentifier(table.schema_name)}.${quoteIdentifier(table.relname)}`, privilege]);
        if (!result.rows[0]?.allowed) failures.push(`${role} lacks ${privilege} on ${key}`);
      }
    }
  }
  for (const role of rules.deniedSchemaCreateRoles ?? []) {
    for (const schema of schemas) {
      const result = await pool.query("SELECT pg_catalog.has_schema_privilege($1,$2,'CREATE') AS allowed", [role, schema]);
      if (result.rows[0]?.allowed) failures.push(`${role} has CREATE on schema ${schema}`);
    }
  }
  return { ok: failures.length === 0, failures, snapshot };
}
