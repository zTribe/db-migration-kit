# @ztribe/db-migration-kit

Shared PostgreSQL migration runner, checksum auditor, local CLI and runtime-security catalog checks for zTribe services.

## Local CLI

Run commands from the root of the service repository.

**Indexer**
```bash
MIGRATION_DATABASE_URL="$DATABASE_URL" node packages/db-migration-kit/bin/db-migrate-kit.js status --config=packages/db-migration-kit/examples/indexer.migration-kit.config.json
MIGRATION_DATABASE_URL="$DATABASE_URL" node packages/db-migration-kit/bin/db-migrate-kit.js audit --config=packages/db-migration-kit/examples/indexer.migration-kit.config.json
```

**Chat (after the shared package is published or checked out into the Chat workspace)**
```bash
MIGRATION_DATABASE_URL="$DATABASE_URL" node packages/db-migration-kit/bin/db-migrate-kit.js status --config=packages/db-migration-kit/examples/chat.migration-kit.config.json
MIGRATION_DATABASE_URL="$DATABASE_URL" node packages/db-migration-kit/bin/db-migrate-kit.js audit --config=packages/db-migration-kit/examples/chat.migration-kit.config.json
```

Both Chat and Indexer consume the shared Kit. Use the migration config in the service checkout when operating on that service.

Apply requires explicit confirmation. Local PostgreSQL:
```bash
MIGRATION_DATABASE_URL="postgres://..." node packages/db-migration-kit/bin/db-migrate-kit.js apply --yes --config=...
```

A remote target is blocked by default. Before using the command below, the Dev database must have an independently provisioned identity marker and the config must include matching `targetIdentity` fields. See [target identity setup](docs/TARGET-IDENTITY.md). The `--allow-remote` flag alone does **not** bypass identity verification:
```bash
MIGRATION_DATABASE_URL="$DEV_DATABASE_URL" node packages/db-migration-kit/bin/db-migrate-kit.js apply --yes --allow-remote --config=...
```

Do not run local tests or CLI apply against Production. `status` and `audit` are read-only; `audit` wraps its catalog/ledger read in a PostgreSQL read-only transaction.

## Prepare a migration from candidate SQL

From a Chat or Indexer checkout with the Kit upgrade fixture wired for candidate
capture, put the proposed SQL outside `db/migrations/`. Install dependencies
and build Indexer before preparing its migration.

```bash
npx --no-install db-migrate-kit prepare chat HEAD ./candidate.sql add_vote_state "Reviewed schema and permissions for vote state" ./checks.sql
npx --no-install db-migrate-kit prepare indexer HEAD ./candidate.sql add_vote_state "Reviewed schema and permissions for vote state" ./checks.sql
```

Use the target branch's pre-change commit in place of `HEAD` when preparing a
merge. Its migration directory must match the checkout's existing SQL exactly.
Pass a review reason that describes the intended change.

The command builds the baseline in an isolated Docker PostgreSQL 17, tries the
candidate as the consumer's non-superuser migration role, and captures the
before/after catalogs. It writes one versioned SQL file and its checksum-bound
review sidecar, then replays the upgrade with the normal service runner on a
fresh container. It executes `checks.sql` after the project's upgrade checks,
inside a rolled-back transaction. The final query must return at least one row
with a unique `check_name` (text) and `passed` (boolean). Check names with false
results are reported. A failed replay or assertion removes the two generated files. The command
requires a catalog change and SQL that runs inside a Kit-managed transaction.
Review the resulting diff and run the service's applicable checks before
committing, including Indexer's `npm run test:db-security` for permission changes.

## Owner-sensitive migration policy (Chat + Indexer)

The shared Kit exports `createOwnerMaintenancePolicy`,
`acquireTemporaryOwnerRole` and `releaseTemporaryOwnerRole`. Both consumers
can declare their own strictly scoped function recipes; **unlisted new**
owner-sensitive migrations fail closed. It does not mix Chat and Indexer role
identities or grant elevated privileges automatically.

A service may use the optional `beforeTransactionalPreflight` /
`afterTransactionalMigration` Runner hooks to acquire and release a
transaction-scoped, externally ADMIN-authorized `SET ROLE` capability.
These hooks run only for normal transactional migrations; nontransactional
migrations never auto-elevate. The entire DDL + ACL + ledger transaction must
succeed or roll back. The service must choose and validate its own migration
login, project identity, owner roles, review digest and deployment target.
Approved recipes and role names remain project-specific configuration.

See `test/owner-maintenance-policy.test.js` for Chat-style timestamp and
Indexer-style counter examples. This is policy/adapter infrastructure,
**not** an authorization to migrate live databases. Only a real PG17
non-superuser upgrade and a target-specific read-only preflight can confirm
a real deployment path.

## Future-migration relation capability preflight

Services may set `capabilityRelationPreflightAfter` in their own
`db/migration-kit.config.json` to the exact **last legacy migration version**.
The Kit validates this version exists and, for migrations after it, checks
`CREATE TABLE / VIEW / SEQUENCE` schema CREATE rights and the actual
`pg_catalog` ownership of common `ALTER/DROP TABLE`, trigger, policy,
index and view changes. It rejects unqualified object names and unsupported
forms instead of guessing. Existing historical SQL before or at the boundary
is unchanged. Owner recipes remain separately reviewed.

This check does **not** execute SQL or inspect arbitrary dynamic `DO`,
complex extension DDL, function-body mutations or all PostgreSQL ownership
operations. It cannot guarantee permission success: PG17 full-history and
non-superuser upgrade replay (including ACL/RLS and failure rollback) must
still run before deployment. It is intentionally an early diagnostic, never
a replacement for the actual migration or live target identity check.

## Library capabilities

- Explicit, ordered migration manifests and SHA-256 checksums.
- PostgreSQL advisory lock to serialize concurrent deploys.
- One transaction per migration; a failed migration rolls back its DDL and ledger row.
- Existing migration checksum/name drift and unknown ledger versions fail closed.
- Explicit marker for non-transactional SQL: `-- migrate:non-transactional` (also accepts `-- migrate:non-transactional-index`).
- Live catalog inspection for schema/table RLS, FORCE RLS, SECURITY DEFINER ownership, fixed `search_path`, PUBLIC/client EXECUTE, effective table DML privileges and schema CREATE privileges.
- Project-specific manifest, role allowlists, schema names and RLS expectations remain in each service config; the package does not invent grants or policies.

## Shared service adapter API (in development)

The shared Runner owns ordered migration execution, checksum drift detection, advisory locks, transaction boundaries, ledger writes, and audit reports. Both Chat and Indexer supply project-specific configuration and safety hooks.

```js
import { applyMigrations, baselineMigrations, auditMigrations, inspectRuntimeSecurity } from "@ztribe/db-migration-kit";

const config = {
  directory: "./sql", // Indexer: ./sql; Chat: ./supabase/migrations
  files: ["001_first.sql", "002_second.sql"],
  schema: "chain", // Chat: app
  ledgerTable: "schema_migrations",
  lockName: "unique-lock-per-service",
  verifyTarget: async (client) => {
    // A production-safe adapter MUST independently verify the database identity
    // using DB-side identity evidence, not the shared Supabase pooler hostname.
  },
  beforeMigrations: async (client) => {
    // Optional project legacy baseline hook (requires separate catalog proof).
  },
  beforeMigration: async (client, migration) => {
    // Destructive migration guard, owner checks, invalid-index repair, etc.
  },
  allowNonTransactional: false,
};
```

**Verified baseline:** `baselineMigrations(pool, {...config, baselineThrough: "001_first", verifyBaseline: async client => /* compare expected vs actual catalog */ true })` requires explicit, successful catalog evidence and records SHA256 checksums without applying SQL. Never use an unconditional `true` in real adapters.

**Indexer compatibility requirements:** restore its `beforeMigration` destructive-reset and invalid-concurrent-index hooks; explicitly allow reviewed non-transactional index migrations. The historic Indexer `baseline-existing-schema` marker requires a legacy-specific policy before switching the live service. Do not silently rewrite historical ledger rows.

**Chat compatibility requirements:** retain its catalog-verified auto-baseline through the existing approved version, destructive guards, TLS certificate handling and project-ref checks; its legacy `status` exit code for pending migrations and current CLI flags must be mapped in the adapter.

## Adoption status

The standalone repo has real PostgreSQL 17 tests for the generic Runner and simulated Chat/Indexer adapter workflows. **Neither live Chat nor live Indexer repo has yet switched to consume this standalone package.** CI success here must not be interpreted as full consumer compatibility or production readiness. Never run against Production until full cross-repo tests and a separately authorized deployment.

### Declarative migration planning

A JSON config can use a fixed `files` manifest or `discovery: "counter"`
(three digits) or `discovery: "timestamp"` (14 UTC digits). Paths resolve
relative to the config. Use `validate` to validate the manifest offline.

Set `targetState` to a JSON document with `version: 1`, a structural
catalog from `readSchemaCatalog` (or `schema: null` for permission-only
exports), and a `permissions` object with arrays for schemas, objects,
columnPrivileges, functions, policies, roles, and memberships.
`plan --from=current.json` prints the diff and proposed SQL.
`review --from=current.json` checks a configured review file with the
plan digest and a nonempty reason. The digest binds an approval to a
specific diff. Require a human repository review for changes to approval
files and the CI workflow.

`generate --from=current.json` prints approved SQL. Add `--name=description`
to write the next forward migration without overwriting an existing file.
Simple schema, table and sequence ACLs and table RLS flags can be rendered.
Plans with unsupported changes require explicit SQL. Plan and generate
operate offline and perform no database writes.

A guarded migration uses `guard: { "version": "...", "before": "before.json" }`
in the shared config. Capture comparable live states using
`readTargetState(client, schemas)`. The Runner checks the reviewed SQL,
compares live state with the before snapshot, and checks the resulting
catalog before inserting the ledger row in the same transaction. The
generated DDL subset includes adding nullable columns of supported built-in
types without defaults. Install independent review for changes to the
config, SQL, and review file using repository protections.

A guard names one transactional migration. Unguarded historical migrations
continue through the existing Runner path. Use comparable PostgreSQL
instances and schema coverage because raw role and ACL state includes
environment-specific entries.

For default enforcement, configure `historicalManifest` as a JSON map of
existing migration versions to their SHA-256 checksums. Freeze that map at
adoption. Every subsequent SQL migration needs a sibling
`<name>.sql.review.json` with the before and after states, review, and SQL
checksum. The generate command writes both files. Explicit SQL can also
use this format and undergo the same transactional catalog checks.


## AI migration drafting: fail fast before prepare

Run from the Chat or Indexer root:

```bash
npm exec -- db-migrate-kit draft-check --config=db/migration-kit.config.json --sql=db/candidates/change.sql --name=change_name
```

This read-only preflight reports machine-readable issue `code`, `severity`, `message`, and `next` actions. It checks Owner recipes, transaction boundaries, SECURITY DEFINER paths and common migration hazards, and provides advisory PostgreSQL AST findings. No database connection or migration file is created. AI must fix errors and explicitly review warnings, then run `db-migrate-kit prepare` with PG17 non-superuser tests. `prepare` now invokes the same preflight before PG17 and before creating the official migration/sidecar. Never treat this preflight as deployment approval.


### Owner-maintenance recipe statement boundary

For new migration candidates, a reviewed Owner recipe authorizes **only** the temporary schema CREATE grant, local role switch, reviewed FUNCTION DDL, role reset and CREATE revoke, in approved order. Other statements (including DO/CALL/SELECT or dynamic DDL) are rejected. Keep unrelated SQL in an independently reviewed migration. `legacyDoVersions` is an explicit compatibility escape hatch for exact preexisting reviewed migration versions with immutable checksum protection; never enable it for new migration candidates. It applies only to historical forMigration() replay, not to new AI candidates. DO/CALL in ordinary candidates generates a manual-review diagnostic and must be validated against PG17.

## Transactional CREATE POLICY capability preflight

For **new, reviewed transactional migrations** only, Kit checks the relation
owner as usual. PostgreSQL deployments can delegate `CREATE POLICY` through
database-side authorization without changing catalog ownership. When an
existing relation fails the ownership preflight, Kit can perform a **generic**
capability test in the same migration transaction: savepoint → create a
temporary **RESTRICTIVE, always-false** policy on the target relation →
roll back to savepoint → release savepoint. Only a successful real SQL check
permits the migration to proceed. The policy never commits.

This applies to any relation and schema; there are no provider-specific,
business-specific, role-specific or table-name allowlists. Non-transactional
migrations, `ALTER/DROP POLICY`, pending `SET ROLE`, missing tables and
all other DDL remain governed by the original fail-closed checks. The actual
migration statement must still execute successfully, pass its Kit checks and
the non-superuser PostgreSQL upgrade tests.


## Advisory pre-draft context

Before writing SQL: `db-migrate-kit pre-draft --config=db/migration-kit.config.json --target=relation:chain.example '--target=function:chain.example_trigger()'` (Chat uses `app` targets). Optional `--snapshot=/path/to/catalog.json --snapshot-source=provided-snapshot` reads an external catalog. Default `migration-target.json` is an **expected target**, not proof of the current database. Use `--operation=create` for a new object not yet in the catalog; default is `modify`, which blocks missing objects. Passing `--snapshot` requires `--snapshot-source=provided-snapshot`. This command is read-only, checks the recorded historical permission-profile prefix/checksum, surfaces owner, ACL, RLS, policies, and missing facts, and never approves migration capability. Inspect real ledger/owner credentials and run PG17 `prepare` afterward.

### Stable permission checkpoint semantics

The recorded permission profile is a **versioned historical checkpoint**, not a live-state cache to refresh after every SQL migration. Replay immutable historical migrations through `profile.baseline.version`, restore roles/Owner/ACL/RLS **at that checkpoint**, then run all remaining historical migrations and candidate SQL in order. A later migration count is normal; `replayPlan` explicitly identifies that suffix and is advisory until the disposable PG17 test runs. Re-capture only for an independently changed out-of-band permission/managed object state, identity or authority drift, and always capture structure, permissions and migration ledger consistently. Supabase SQL Editor identity alone does not prove the real migration login's capabilities.

### v2 SQL Editor export in pre-draft CLI

Use a Kit-compatible **single-row** SQL Editor CSV export with column `complete_snapshot`; pass it to `db-migrate-kit pre-draft --snapshot=chat-prod.csv --snapshot-source=provided-snapshot --target=relation:app.messages`. The v2 exporter includes the unchanged `postgres_version`, `roles`, `memberships`, `schemas`, `relations`, `column_acls`, `functions`, `policies`, `default_acls`, `extensions`, `database_acl`, `migration_ledger` fields expected by `parseLiveEnvironmentSnapshot`, plus an eight-section `structural_catalog`. Only v2 exports with all requested schemas present become pre-draft target state. The recorded Production permission checkpoint can predate the current ledger; a Dev migration suffix ahead of Production is `upgrade_pending` (review), while checksum disagreements and divergent historical ledgers remain blockers. Exported function definitions may contain embedded credentials: inspect before sharing.

### Supabase managed Realtime policy pre-draft

`--operation=policy-create` is a **narrow advisory** mode for Chat `relation:realtime.messages`
with a complete `--snapshot-source=provided-snapshot` SQL Editor export showing
`supabase_realtime_admin` as Owner and the recorded migration role `postgres`.
It avoids a false `PROFILE_SCHEMA_UNCOVERED` hard block solely because the
reusable business permission profile covers `app` rather than Supabase's managed
`realtime` schema. **No other schema, table, role, or operation receives the
exception.** It cannot assert Supabase's provider-level `supautils` delegation:
the Kit's transactional `CREATE POLICY` probe on the real executing role,
the immutable migration ledger and effective RLS behavior remain mandatory.
`ALTER TABLE realtime.messages` is never permitted by this special mode.
See https://supabase.com/kb/troubleshooting/realtime-must-be-owner-of-table-messages .
