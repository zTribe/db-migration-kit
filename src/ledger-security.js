import { qualifiedName, quoteIdentifier } from "./identifiers.js";

/**
 * Harden migration-ledger access in the SAME transaction as ledger creation.
 * Never grant write access to an audit or application role.
 */
export async function hardenMigrationLedger(client, options) {
  const {schema="public",ledgerTable="schema_migrations",auditRole=null,clientRoles=["anon","authenticated","service_role"]}=options;
  const ledger=qualifiedName(schema,ledgerTable);
  const names=[...new Set(clientRoles)];
  if(auditRole && names.includes(auditRole))throw new Error("audit role cannot also be a client role");
  await client.query("SELECT pg_catalog.set_config('lock_timeout','3s',true)");
  await client.query(`REVOKE ALL ON TABLE ${ledger} FROM PUBLIC`);
  const roles=[...new Set([...names,...(auditRole?[auditRole]:[])])];
  const existing=roles.length?(await client.query(
    "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname=ANY($1::text[])",[roles],
  )).rows.map(row=>row.rolname):[];
  for(const role of existing) {
    await client.query(`REVOKE ALL ON TABLE ${ledger} FROM ${quoteIdentifier(role)}`);
  }
  await client.query(`ALTER TABLE ${ledger} ENABLE ROW LEVEL SECURITY`);
  await client.query(`ALTER TABLE ${ledger} FORCE ROW LEVEL SECURITY`);
  // FORCE RLS also applies to the table owner. Allow the trusted migration
  // identity to continue recording checksums; no access for app roles.
  const migrator=(await client.query("SELECT current_user AS username")).rows[0].username;
  if(names.includes(migrator) || auditRole===migrator)throw new Error("untrusted migrator role");
  const writePolicy="db_migration_kit_migrator";
  const existsWriter=await client.query("SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid=$1::regclass AND polname=$2",[ledger,writePolicy]);
  if(!existsWriter.rowCount) await client.query(
    `CREATE POLICY ${quoteIdentifier(writePolicy)} ON ${ledger} FOR ALL TO ${quoteIdentifier(migrator)} USING (true) WITH CHECK (true)`,
  );
  // Only this one table and one read-only audit role; no default privileges.
  if(auditRole){
    if(!existing.includes(auditRole))throw new Error(`required ledger audit role ${auditRole} is missing`);
    await client.query(`GRANT USAGE ON SCHEMA ${quoteIdentifier(schema)} TO ${quoteIdentifier(auditRole)}`);
    await client.query(`GRANT SELECT ON TABLE ${ledger} TO ${quoteIdentifier(auditRole)}`);
    const policy="db_migration_kit_audit_select";
    const existingPolicy=await client.query(`SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid=$1::regclass AND polname=$2`,[ledger,policy]);
    if(!existingPolicy.rowCount)
      await client.query(`CREATE POLICY ${quoteIdentifier(policy)} ON ${ledger} FOR SELECT TO ${quoteIdentifier(auditRole)} USING (true)`);
  }
  return {hardened:true,ledger,auditRole};
}
