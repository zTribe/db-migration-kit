/**
 * Stable issue categories for AI retry loops. Never bypass a gate based on the
 * category: diagnostics are hints, not permission to alter historical SQL.
 */
export function explainPrepareFailure(error,stage="unknown") {
  const message=String(error?.message ?? error);
  const cases=[
    [/ADMIN OPTION|permission denied to grant role|missing external ADMIN/i,
      "OWNER_ADMIN", "Check the migrator's externally approved ADMIN OPTION for the specific runtime owner on the disposable PG17 fixture; do not grant superuser or broaden runtime privileges."],
    [/cannot SET ROLE|permission denied to set role|not permitted to set role/i,
      "OWNER_SET", "Inspect the exact owner role and SET membership, reviewed recipe and temporary lease; test using the same non-superuser identity."],
    [/must be owner|owner is |cannot alter|lacks CREATE|no CREATE on schema|permission denied/i,
      "OBJECT_CAPABILITY", "Inspect the target object's owner, migration login, schema CREATE and ACL; prefer an additive/versioned RPC when direct changes are not authorized."],
    [/checksum|historical migration|Base migration changed|migration manifest|unknown applied/i,
      "MIGRATION_HISTORY", "Compare the Git base and migration ledger/checksums; never edit an applied migration or its history record."],
    [/requires a review|Review SQL|guard|snapshot|catalog mismatch|Migration assertions failed/i,
      "REVIEW_OR_ASSERTIONS", "Regenerate the candidate and actual PG17 before/after review; inspect failed check_name rows rather than editing the expected snapshot."],
    [/syntax error|does not exist|undefined column|undefined table|function .* does not exist/i,
      "SQL_OR_DEPENDENCY", "Inspect SQL syntax, schema qualification, actual PG17 object definitions and dependent SQL/RPC callers."],
    [/did not execute and pass|--test-name-pattern|skip guards/i,
      "TEST_SELECTION", "Check fixture test-name pattern and skip conditions; do not accept an exit-zero when the intended test never ran."],
    [/Docker|docker|Local PostgreSQL did not start|pg_isready/i,
      "LOCAL_PG17", "Start local Docker with PG17 and retry; this is an environment failure, not a successful migration test."],
  ];
  const match=cases.find(([pattern])=>pattern.test(message));
  return {
    status:"failed", stage,
    code:match?.[1]??"PREPARE_FAILED",
    message:message.slice(0,2000),
    next:match?.[2]??"Read the first failed stage and PostgreSQL error; fix the candidate or test environment, then restart prepare from the same Git base.",
    canPublishMigration:false
  };
}
