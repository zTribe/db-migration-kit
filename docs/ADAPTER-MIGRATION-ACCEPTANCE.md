# Shared migration hardening: adapter integration checklist

These modules are **opt-in** so existing Indexer/Chat production deployments do
not change behavior until both adapters have passed their own full migration
and runtime-security regression suites.

## Ledger ACL

Set `ledgerSecurity: {clientRoles:["anon","authenticated","service_role"], auditRole:"chat_migration_audit"}`
in the migration runner config. The audit role **must already exist** and be
managed outside the migration SQL. The runner creates/hardens the ledger in one
transaction. It revokes PUBLIC and client grants, enables and forces RLS,
allows the trusted migration role to record checksums, and grants only SELECT
to the designated audit role. Effective inherited DML/SELECT privileges are
checked and cause rollback.

**CAUTION:** Do not enable on a populated database until you have reviewed
its existing RLS policies, migration-role ownership, and external monitoring
role dependencies. This setting does not replace independent audit-user
credential protection. The migration role is privileged by design.

## Structural compatibility audit

`readSchemaCatalog(pool,["chain","api"])` returns a deterministic,
normalized snapshot containing tables/views/sequences, columns (type, default,
identity), constraints, indexes (including validity), triggers, functions
(including source), RLS policies and publication membership.

`compareSchemaCatalog(expected,actual)` reports missing, unexpected and
changed objects; use `auditSchemaCatalog` for read-only comparisons.
Structural compatibility is separate from the runtime ACL/security checker.
Review and pin the expected snapshot at an immutable migration manifest
revision. Publication membership and other externally managed Supabase
objects may require a service-specific scope/adapter.

## Auto baseline

Use `autoBaseline:{through:"<reviewed-prefix>",schemas:["app"],
expectedCatalog:<approved-post-prefix-snapshot>}`.

The runner validates the existing catalog **before creating the ledger** when
a database has no migration records. Only a complete exact catalog match
allows it to record a baseline prefix; an empty DB runs migrations normally.
A difference rejects a populated database before any ledger DDL. A baseline
never executes its historical SQL files. Do not use a live Production
snapshot as the authority without independent SQL/revision review.

Existing Indexer legacy ledger sentinel values require explicitly pinned
`legacyBaselineChecksums`. Preserve existing Chat migration catalog
exclusions/PG-version compatibility through its adapter; do not silently
replace the Chat catalog baseline with an unreviewed snapshot.

## Recover failed concurrent index builds

For explicit invalid-index repair, call
`recoverInvalidConcurrentIndex(pool,{lockName,verifyTarget}, {
 schema:"chain",index:"index_name",table:"table_name",confirm:true
})`.
The function obtains the **same advisory lock** as migration execution,
runs independent target identity verification, confirms that the index is
invalid and belongs to the expected table, and only then executes
`DROP INDEX CONCURRENTLY`. It refuses to delete valid indexes.

Nontransactional DDL may have already committed partial effects; recovery is
an explicit operational action, **not an automatic retry**. Never run this
against production without change approval and exact index/target review.

## Remaining adapter acceptance gates

1. Run every checked-out Indexer/Chat migration against isolated PostgreSQL
   with faithful Supabase roles/permissions and required extensions.
2. Exercise both fresh install and real historical-baseline shapes; verify
   different PG versions and deterministic catalog differences.
3. Run existing service-specific runtime security assertions and business
   structure invariants unchanged; preserve the separate migration/runtime
   credential boundary, TLS configuration and launch fail-closed semantics.
4. Review migration SQL dynamic DDL and any role ownership handoffs under a
   real non-superuser login. Do not infer permissions from SQL regex alone.
5. Only after these steps review promotion of generated `needs_review`
   security candidates to approved service-owned policies.

The package's PostgreSQL 17 fixture suite exercises new generic behavior,
but does **not** establish full parity with the two consumers' historical
migration chains or Production Supabase configuration.
# Consumer migration release gate

Use `verifyMigrationUpgrade` from `@ztribe/db-migration-kit/verify-migration-upgrade` in the consumer integration suite. Pass the separate migration pool and role, expected ledger snapshots (`before` and `after`), a `readLedger(pool)` callback, the normal `apply(pool)` entry point adapted to return the applied versions, and `verifyPermissions(pool)` for consumer-specific catalog assertions.

Indexer separates the migration connection from the runtime connection. Carry that separation into the test harness and verify the identity on the connection that actually executes the SQL. Testing runtime permissions after applying migrations as a superuser does not establish that the production migrator can apply them.

1. In disposable PostgreSQL, restore a representative deployed ledger and its matching schema, object owners, grants, and role memberships. Use a fixture administrator to provision this state.
2. Open a separate connection as the deployment-equivalent migration role. Assert `rolsuper=false` and check effective owner membership and grant authority before running the consumer's normal entry point. Use the exact checked-out migration manifest, including checksum checks and consumer hooks.
3. Apply the entire pending suffix. Verify the resulting ledger, a no-op repeat, final object ownership, and effective ACLs as the runtime and client roles. Include a failing transactional migration and verify both DDL rollback and absence of its ledger row.
4. Make this a required consumer CI check. Keep fresh-install and superuser tests for their own coverage. The generic Kit tests cannot supply consumer-specific historical schema or production-equivalent role fixtures.

Chat's `51 → 52` upgrade exposed why this matters: checking that a file contains a temporary grant does not establish that PostgreSQL executes it before every owner-sensitive statement. Execute the real SQL, and verify temporary privileges are gone afterwards.
