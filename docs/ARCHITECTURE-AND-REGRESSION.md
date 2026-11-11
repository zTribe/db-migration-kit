# Migration Kit architecture and regression contract

Status: implementation in progress. This is a checklist, not a claim that all checks are implemented.

## Boundary

- **Core**: ordered manifest, immutable SHA-256 checksums, ledger validation, locking, transactional apply, read-only audit.
- **PostgreSQL catalog**: object inventory, ACL/effective grants, ownership, RLS/FORCE RLS, SECURITY DEFINER and fixed search_path.
- **Service adapters**: Indexer and Chat own their migrations, schema snapshots, role matrix, baseline policy, project identity, and startup assertions.
- **CLI**: status/audit/security default to read-only; apply must be explicit, with remote target identity checks.
- **CI**: unit tests and isolated PostgreSQL 17 integration tests, including real role creation and positive/negative ACL assertions.
- **Production**: never infer identity from pooler hostname. Database identity must be checked independently before any write. Production apply is out of scope until a separately reviewed policy is implemented.

## Failure modes learned from Indexer / Chat

| Incident | Required regression | Current status |
|---|---|---|
| Applied SQL edited; checksum drift | Reject historical drift without touching DB | Implemented |
| Existing DB baseline vs fresh install | Both histories must yield equivalent catalog | Adapter-specific, pending |
| Migration uses wrong function owner | Actual pg_proc owner assertions | Partial |
| SET ROLE lacks membership | Execute migrations as realistic non-superuser roles | Pending |
| SQL syntax error only discovered on deployment | Execute entire migration chain in PG17 | Adapter-specific, pending |
| RLS / schema / function grants differ | Effective catalog privileges for each runtime role | Partial |
| SECURITY DEFINER with unsafe search_path | Enumerate all functions, deny unsafe path and PUBLIC execute | Partial |
| Wrong Supabase project/Dev vs Main | Explicit project identity + DB metadata preflight | Pending |
| Dev/Main diverged migration history | Separate ledgers, immutable history, audit before apply | Partial |
| Reorg-safe balance API role cleanup | Representative permission/owner assertions | Pending |
| Failed migration leaves partial state | Transaction rollback and ledger atomicity | Implemented for transactional SQL |
| Nontransactional SQL leaves partial state | Explicit opt-in; recovery playbook | Opt-in guard implemented, recovery pending |
| Audit accidentally writes | READ ONLY transaction and before/after ledger check | Implemented |
| CLI points at Production | Reject unless explicit verified identity policy | Pending; current --allow-remote alone is insufficient |
| CI skipped PG tests after unit failure | Independent CI jobs | Implemented in shared repo |
| Manifest traversal or unexpected order | Canonical path and ordered manifest validation | Implemented |

## Release gates

1. No historical migration files or ledger rows modified.
2. Public API is versioned; adapters pinned to an immutable release/commit.
3. Fresh DB and baseline DB produce matching schema catalogs for each service.
4. All required runtime roles exist in tests, including inherited privileges and forbidden grants.
5. All service migrations run against real PG17 in CI, not SQL-text matching alone.
6. Dev/Main target identity cannot be inferred from shared pooler host.
7. CI green in shared library, Indexer and Chat, with no skipped required jobs.
8. Dev deployment audit checked before proposing production rollout.
9. Security review includes secret scanning and public repository exposure review.
10. Production write actions remain blocked until explicitly authorized.

## Known gaps to resolve before adoption

- Baseline checksum policy currently exempts baseline rows from drift comparison. Define and test canonical baseline evidence.
- SECURITY DEFINER inspection needs strict expected function inventory and exact safe path policy.
- Nontransactional SQL needs idempotence/recovery protocol and dedicated tests.
- CLI must not accept a remote production target merely because --allow-remote is passed.
- No end-to-end adapter migration has yet been proven for both services.
