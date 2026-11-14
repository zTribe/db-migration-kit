/** Capture raw catalog facts in the same transaction as the migration. */
export async function readPermissionState(client, schemas) {
  const { rows: [state] } = await client.query(`
    WITH relations AS (
      SELECT c.*, n.nspname AS schema
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname=ANY($1::text[]) AND c.relkind IN ('r','p','v','m','S','f')
    )
    SELECT
      ARRAY(SELECT jsonb_build_object('scope', 'current', 'owner', pg_catalog.pg_get_userbyid(datdba),
        'acl', to_jsonb(ARRAY(SELECT entry::text FROM unnest(coalesce(datacl, pg_catalog.acldefault('d', datdba))) entry ORDER BY entry::text)))
        FROM pg_catalog.pg_database WHERE datname=current_database()) AS "databasePrivileges",
      ARRAY(SELECT jsonb_build_object('owner', pg_catalog.pg_get_userbyid(d.defaclrole),
        'schema', coalesce(n.nspname, ''), 'kind', d.defaclobjtype,
        'acl', to_jsonb(ARRAY(SELECT entry::text FROM unnest(d.defaclacl) entry ORDER BY entry::text)))
        FROM pg_catalog.pg_default_acl d LEFT JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace) AS "defaultPrivileges",
      ARRAY(SELECT to_jsonb(x) FROM (
        SELECT nspname AS schema, pg_catalog.pg_get_userbyid(nspowner) AS owner, nspacl::text AS acl
        FROM pg_catalog.pg_namespace WHERE nspname=ANY($1::text[])
      ) x) AS schemas,
      ARRAY(SELECT to_jsonb(x) FROM (
        SELECT schema, relname AS name, relkind AS kind, pg_catalog.pg_get_userbyid(relowner) AS owner,
               relrowsecurity AS rls, relforcerowsecurity AS force_rls, relacl::text AS acl FROM relations
      ) x) AS objects,
      ARRAY(SELECT to_jsonb(x) FROM (
        SELECT c.schema, c.relname AS relation, a.attname AS column_name, a.attacl::text AS acl
        FROM relations c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
        WHERE a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
      ) x) AS "columnPrivileges",
      ARRAY(SELECT to_jsonb(x) FROM (
        SELECT n.nspname AS schema, p.proname AS name, pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,
               pg_catalog.pg_get_userbyid(p.proowner) AS owner, p.prosecdef AS security_definer,
               p.proconfig AS configuration, p.proacl::text AS acl
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname=ANY($1::text[]) AND p.prokind IN ('f','p')
      ) x) AS functions,
      ARRAY(SELECT to_jsonb(x) FROM (
        SELECT schemaname AS schema, tablename, policyname, permissive, roles, cmd, qual, with_check
        FROM pg_catalog.pg_policies WHERE schemaname=ANY($1::text[])
      ) x) AS policies,
      ARRAY(SELECT to_jsonb(x) FROM (
        SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolinherit, rolreplication
        FROM pg_catalog.pg_roles
      ) x) AS roles,
      ARRAY(SELECT to_jsonb(x) FROM (
        SELECT pg_catalog.pg_get_userbyid(member) AS member, pg_catalog.pg_get_userbyid(roleid) AS parent,
               admin_option, inherit_option, set_option FROM pg_catalog.pg_auth_members
      ) x) AS memberships
  `, [schemas]);
  return state;
}
