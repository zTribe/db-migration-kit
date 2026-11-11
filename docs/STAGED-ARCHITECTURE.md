# Staged migration architecture (review proposal)

Status: design review; not yet fully implemented. Do not use on production.

## Principle

A single orchestration pipeline with independently testable stages and typed results. No parallel checks against mutable migration state. Every stage has explicit input/output and a fail-closed gate. Read-only inspection must never implicitly create a ledger or grant privileges.

```text
CLI / service adapter
  -> 0. parse and validate manifest/config
  -> 1. connect + TLS + independently verify database/project identity and environment
  -> 2. inspect read-only: ledger/checksums, current catalog snapshot, pending plan
  -> 3. verify prerequisites: roles, ownership, SET ROLE capability, SQL/extension compatibility
  -> 4. preflight: plan + human/deployment authorization for writes
  -> 5. acquire scoped lock + revalidate identity and ledger under lock
  -> 6. apply one migration/transaction at a time (with crash-safe ledger)
  -> 7. verify postmigration catalog and runtime security matrix
  -> 8. emit structured audit report and deploy health signal
```

**Critical limitation:** Post-migration catalog verification cannot roll back previously committed per-migration transactions. A strict preflight can prevent many failures, but never promise automatic rollback of an already committed migration. Consider reversible test DB clone before deployment and separate remediation migrations.

## Components

| Layer | Responsibility | Excludes |
|---|---|---|
| manifest | order, paths, SQL bytes, checksums and version uniqueness | no database queries |
| identity | TLS connection and trusted project identity proof | no DDL |
| ledger | immutable applied history, baseline policy, compatibility and unknown migrations | no DDL beyond explicit setup phase |
| catalog | snapshot of schemas, relations, functions, ACLs, owners, roles, memberships, policies, proconfig | no business rules |
| policy | exact expected object inventory, privilege matrix, SECURITY DEFINER, RLS and search_path | no database mutations |
| planner | deterministic pending migrations and risk classification | no apply |
| runner | locks, timeouts, transaction boundaries, hooks and ledger writes | no service-specific security rules |
| auditor | read-only pipeline, structured evidence and difference report | no apply |
| adapters | Indexer/Chat migrations, role expectations, expected catalog, baseline hooks | no generic core reimplementation |
| cli | validated args, safe defaults, clear diagnostic output, redaction | no independent migration logic |

## Precedence, no duplicate checking

- Manifest validation happens exactly once, before any connection.
- Connection identity is checked at first connection and *rechecked* after acquiring lock before write; this is deliberate TOCTOU defense, not accidental duplication.
- Ledger plan is read once for status; apply rereads under lock because concurrent deploys can change it.
- Catalog is read once as a snapshot per checkpoint; post-apply is a new snapshot by design.
- Security predicates run on catalog snapshot rather than issuing per-role/per-object queries repeatedly.
- Only the adapter specifies expected grants/functions/schema inventory. Core runs generic predicates.
- Optional checks cannot silently pass when expected objects are absent.
- `status`, `audit`, `security` are read-only and should use a restricted DB account.

## Incident-driven gates

1. Wrong Dev/Main target: independent DB identity; never trust the shared pooler host alone.
2. Applied migration changed: checksum/name history immutable, baseline separately evidenced.
3. Nonexistent objects / wrong owner: exact inventory and pg_catalog owner/ACL checks.
4. SET ROLE failures: real PostgreSQL non-superuser privilege tests.
5. Syntax / dialect: exercise full fresh migration chain on PG17 (plus Supabase role fixture).
6. Existing DB baseline: compare fresh install against baseline-upgraded final catalog.
7. SECURITY DEFINER: exact signatures, owner allowlist, grant matrix and immutable safe search_path.
8. Reorg / app private tables: role-scoped effective privileges, RLS and FORCE RLS.
9. Nontransactional SQL: explicit opt-in, idempotence review and recovery playbook.
10. Audit drift: independent CI job and read-only PostgreSQL role; audit must leave ledger unchanged.

## Adoption gates

- Shared library unit and real PG17 integration tests green.
- Indexer and Chat adapter full-chain migrations green on fresh and baselined databases.
- All catalog assertions verified with positive and negative privilege fixtures.
- CLI rejects unverified remote apply.
- No bypass flags that transform an unverified environment into a trusted one.
- Pin reviewed immutable release in both consumers.
- No production apply before separate explicit authorization.
