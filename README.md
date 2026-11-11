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

The Chat manifest is included as a ready-to-use config, but the CLI is not yet installed in the separate Chat repository because this package is currently hosted in the private Indexer repository.

Apply requires explicit confirmation. Local PostgreSQL:
```bash
MIGRATION_DATABASE_URL="postgres://..." node packages/db-migration-kit/bin/db-migrate-kit.js apply --yes --config=...
```

A remote target is blocked by default. Before using the command below, the Dev database must have an independently provisioned identity marker and the config must include matching `targetIdentity` fields. See [target identity setup](docs/TARGET-IDENTITY.md). The `--allow-remote` flag alone does **not** bypass identity verification:
```bash
MIGRATION_DATABASE_URL="$DEV_DATABASE_URL" node packages/db-migration-kit/bin/db-migrate-kit.js apply --yes --allow-remote --config=...
```

Do not run local tests or CLI apply against Production. `status` and `audit` are read-only; `audit` wraps its catalog/ledger read in a PostgreSQL read-only transaction.

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
