import assert from "node:assert/strict";

/**
 * Exercise a consumer's normal migration entry point on a disposable database.
 * The caller provisions the historical fixture and supplies its migration pool.
 */
export async function verifyMigrationUpgrade({
  pool, migrationRole, before, after, readLedger, apply, verifyPermissions,
}) {
  const { rows: [identity] } = await pool.query(`
    select current_user as role, session_user as login, rolsuper
    from pg_catalog.pg_roles where rolname = current_user
  `);
  assert.deepEqual(identity, { role: migrationRole, login: migrationRole, rolsuper: false });
  assert.deepEqual(await readLedger(pool), before, "historical migration ledger");
  await apply(pool);
  assert.deepEqual(await readLedger(pool), after, "upgraded migration ledger");
  const repeated = await apply(pool);
  assert.deepEqual(repeated, [], "repeated upgrade must apply no migrations");
  assert.deepEqual(await readLedger(pool), after, "ledger after repeated upgrade");
  await verifyPermissions(pool);
}
