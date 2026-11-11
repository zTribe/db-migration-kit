import { quoteIdentifier } from "./identifiers.js";
import { inventorySecurityObjects, COLUMN_PERMISSIONS, SEQUENCE_PERMISSIONS } from "./object-model.js";

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
    ...(rules.objectPolicies ?? []).flatMap(item=>[
      ...Object.keys(item.privileges ?? {}),
      ...(item.kind === "role" ? [item.key] : []),
    ]),
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
    const schemaObjects=(await client.query(`
      SELECT n.nspname AS schema_name, r.rolname AS owner_name
      FROM pg_catalog.pg_namespace n
      JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner
      WHERE n.nspname=ANY($1::text[]) ORDER BY n.nspname
    `,[schemas])).rows;
    const columns=(await client.query(`
      SELECT n.nspname AS schema_name,c.relname AS table_name,
             a.attname AS column_name,r.rolname AS owner_name
      FROM pg_catalog.pg_attribute a
      JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
      WHERE n.nspname=ANY($1::text[]) AND c.relkind IN ('r','p')
        AND a.attnum>0 AND NOT a.attisdropped
      ORDER BY n.nspname,c.relname,a.attnum
    `,[schemas])).rows;
    const sequences=(await client.query(`
      SELECT n.nspname AS schema_name,c.relname,r.rolname AS owner_name
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
      WHERE n.nspname=ANY($1::text[]) AND c.relkind='S'
      ORDER BY n.nspname,c.relname
    `,[schemas])).rows;
    const policies=(await client.query(`
      SELECT n.nspname AS schema_name,c.relname AS table_name,
        p.polname AS policy_name,p.polpermissive AS permissive,p.polcmd AS command,
        CASE WHEN p.polroles=ARRAY[0]::oid[] THEN ARRAY['PUBLIC']::text[]
             ELSE ARRAY(SELECT rolname FROM pg_catalog.pg_roles WHERE oid=ANY(p.polroles) ORDER BY rolname) END AS roles,
        pg_catalog.pg_get_expr(p.polqual,p.polrelid) AS using_expr,
        pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) AS check_expr
      FROM pg_catalog.pg_policy p
      JOIN pg_catalog.pg_class c ON c.oid=p.polrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname=ANY($1::text[])
      ORDER BY n.nspname,c.relname,p.polname
    `,[schemas])).rows;
    const memberships=roles.length ? (await client.query(`
      SELECT member_role.rolname AS member, parent_role.rolname AS parent,
             m.inherit_option, m.set_option, m.admin_option
      FROM pg_catalog.pg_auth_members m
      JOIN pg_catalog.pg_roles member_role ON member_role.oid=m.member
      JOIN pg_catalog.pg_roles parent_role ON parent_role.oid=m.roleid
      WHERE member_role.rolname=ANY($1::text[])
      ORDER BY member_role.rolname,parent_role.rolname
    `,[roles])).rows : [];
    const privileges = {schemas: {}, tables: {}, functions: {}, columns: {}, sequences: {}};
    // Resolve effective permissions once. Unknown roles stay absent and fail the policy gate.
    for (const role of roles.filter(name => known.has(name))) {
      privileges.schemas[role] = {};
      privileges.tables[role] = {};
      privileges.functions[role] = {};
      privileges.columns[role] = {};
      privileges.sequences[role] = {};
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
      for (const col of columns) {
        const key=`${col.schema_name}.${col.table_name}.${col.column_name}`;
        const relation=`${quoteIdentifier(col.schema_name)}.${quoteIdentifier(col.table_name)}`;
        const {rows:grants}=await client.query(
          `SELECT ${COLUMN_PERMISSIONS.map((p,i)=>`pg_catalog.has_column_privilege($1,$2,$3,'${p}') AS p${i}`).join(", ")}`,
          [role,relation,col.column_name],
        );
        privileges.columns[role][key]=Object.fromEntries(COLUMN_PERMISSIONS.map((p,i)=>[p,grants[0][`p${i}`]]));
      }
      for (const sequence of sequences) {
        const key=`${sequence.schema_name}.${sequence.relname}`;
        const qualified=`${quoteIdentifier(sequence.schema_name)}.${quoteIdentifier(sequence.relname)}`;
        const {rows:grants}=await client.query(
          `SELECT ${SEQUENCE_PERMISSIONS.map((p,i)=>`pg_catalog.has_sequence_privilege($1,$2,'${p}') AS p${i}`).join(", ")}`,
          [role,qualified],
        );
        privileges.sequences[role][key]=Object.fromEntries(SEQUENCE_PERMISSIONS.map((p,i)=>[p,grants[0][`p${i}`]]));
      }
      for (const fn of base.functions) {
        const key = `${fn.schema_name}.${fn.proname}(${fn.identity_args})`;
        const result = await client.query("SELECT pg_catalog.has_function_privilege($1,$2,'EXECUTE') AS allowed", [role,fn.oid]);
        privileges.functions[role][key] = {EXECUTE:result.rows[0].allowed};
      }
    }
    await client.query("COMMIT");
    active = false;
    const snapshot={tables:base.tables,functions:base.functions,roles:roleRows,privileges,schemas,
      schemaObjects,columns,sequences,policies,memberships};
    snapshot.inventory=inventorySecurityObjects(snapshot);
    return snapshot;
  } catch (error) {
    if (active) await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {client.release();}
}
