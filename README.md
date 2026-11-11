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

A remote target is blocked by default. Only after independently verifying that the connection points to **Dev**, explicitly add `--allow-remote`:
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

## Current hosting status

The package currently lives under `packages/db-migration-kit` in the private `zTribe/zTribe-indexer` repository and is consumed by Indexer as a workspace package. It is **not yet published to npm or hosted in a standalone public repository**, and Chat has not yet been switched to consume it. Cross-repository reuse becomes straightforward once the package is published or moved to a repository both projects can access from local development, CI and Railway.
