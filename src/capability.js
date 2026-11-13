const FUNCTION_DDL = /\b(?:create\s+or\s+replace|drop|alter)\s+function\s+((?:[a-z_][a-z0-9_$]*\.)?[a-z_][a-z0-9_$]*)\s*\(/ig;

function unquoteIdentifier(value) { return value.replaceAll('"', ''); }

/** Check owner/schema capabilities before owner-sensitive function DDL runs. */
export async function preflightMigrationCapabilities(client, sql) {
  const targets = [];
  for (const match of sql.matchAll(FUNCTION_DDL)) {
    const qualified = match[1].split('.');
    targets.push({ schema: unquoteIdentifier(qualified.length === 2 ? qualified[0] : 'public'), name: unquoteIdentifier(qualified.at(-1)) });
  }
  if (!targets.length) return;
  const plannedCreate = new Set([...sql.matchAll(/grant\s+create\s+on\s+schema\s+([a-z_][a-z0-9_$]*)\s+to\s+([a-z_][a-z0-9_$]*)/ig)].map(match => `${match[1].toLowerCase()}:${match[2].toLowerCase()}`));
  const plannedMembership = new Set([...sql.matchAll(/grant\s+([a-z_][a-z0-9_$]*)\s+to\s+(?:current_user|%I[^\n]*current_user)/ig)].map(match => match[1].toLowerCase()));
  const identity = await client.query(`select current_user as role, coalesce((select rolsuper from pg_catalog.pg_roles where rolname=current_user),false) as superuser`);
  if (identity.rows[0]?.superuser) return;
  for (const target of targets) {
    const schema = await client.query("select has_schema_privilege(current_user,$1,'CREATE') as can_create", [target.schema]);
    if (!schema.rows[0]?.can_create && ![...plannedCreate].some(key => key.startsWith(`${target.schema.toLowerCase()}:`))) throw new Error(`migration capability denied: ${identity.rows[0]?.role} lacks CREATE on schema ${target.schema} for function ${target.schema}.${target.name}`);
    const functions = await client.query(`
      select p.oid::regprocedure::text as signature, owner_role.rolname as owner,
             pg_catalog.pg_has_role(current_user, owner_role.oid, 'USAGE') as can_alter
      from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid=p.pronamespace
      join pg_catalog.pg_roles owner_role on owner_role.oid=p.proowner
      where n.nspname=$1 and p.proname=$2`, [target.schema, target.name]);
    for (const row of functions.rows) if (!row.can_alter && !plannedMembership.has(row.owner.toLowerCase())) throw new Error(`migration capability denied: ${identity.rows[0]?.role} cannot alter ${row.signature}; owner is ${row.owner}`);
  }
}
