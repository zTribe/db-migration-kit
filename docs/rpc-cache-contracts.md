# Protected RPC → cache dependency auditing (experimental)

This additive, read-only API is not a migration runner. It does not apply SQL,
modify ledgers, change permissions, write Redis, or approve releases.

## Required integration order

1. Rebuild each project's actual **PostgreSQL 17** database from committed
   historical migrations using the project's existing Kit runner.
2. In PR-upgrade tests, capture a catalog from the real pool **before** applying
   pending migrations; apply them as a non-superuser; capture another catalog
   afterward. Run full zero-to-head replay independently.
3. Extract project-owned protected RPC contracts from the same repository; never
   put zTribe Chat or Indexer table names into Kit.
4. Use `compareRpcCatalogContracts(before, after, identities)` to detect
   signature/implementation/security changes. Use
   `auditRpcTableDependencies(after, contracts)` to flag lexical table-reference
   mismatches. At first baseline, audit the full-replay catalog as well.
5. Any `requiresReview` report **must fail an automated approval gate** until
   independently reviewed. Even if no mismatch is found, these APIs always
   return `releaseApproved: false` and `dependencyGraphComplete: false`.
6. Independently check Redis readers/writers, data-only SQL changes, behavioral
   parity, stale cache/versioning, and historical migration ledger/ACL rules.
7. Verify that workflows actually invoked all mandatory stages, including
   injected negative tests; a skipped test must not count as certification.

## Supported and unsupported evidence

`auditRpcTableDependencies` examines `pg_get_functiondef` SQL bodies. It
recognizes common qualified `FROM`, `JOIN`, `INSERT INTO`, `UPDATE`,
`DELETE FROM`, and `TRUNCATE` table references; recursively visits
uniquely resolved, schema-qualified calls.

This is a **conservative lexical aid, not a complete SQL AST parser**. Dynamic
SQL, overloaded/recursive calls, unqualified relations and unsupported function
bodies are flagged. Even a warning-free report does not prove completeness:
views, triggers, non-ordinary statements, function language semantics,
`search_path`, privileges, data changes and Redis consumer behavior require
additional analysis. PostgreSQL's `pg_depend` is useful evidence but
insufficient for every PL/pgSQL body dependency.

## Example (advisory, not an approval gate)

```js
import {
  readSchemaCatalog,
  compareRpcCatalogContracts,
  auditRpcTableDependencies,
} from "@ztribe/db-migration-kit";

const before = await readSchemaCatalog(pool, ["chain", "api"]);
// Apply the actual pending migration using existing project Kit runner.
const after = await readSchemaCatalog(pool, ["chain", "api"]);
const drift = compareRpcCatalogContracts(before, after, rpcIdentities);
const dependencies = auditRpcTableDependencies(after, [
  { id: "api.token_candles", tables: ["chain.candles", "chain.tokens"] },
]);
if (drift.requiresReview || dependencies.requiresReview)
  throw new Error("Protected RPC review required");
// This DOES NOT constitute release approval.
```

Note: The sample uses a project-specific RPC solely to illustrate the
consumer-owned contract; Kit itself contains no business-specific rules.

## Versioning

Consumers must pin an immutable Kit version/commit and update both
`package.json` and the lockfile. Do not tag/publish a new package or merge the
feature branch until the full consumer upgrade and Redis verification passes.
