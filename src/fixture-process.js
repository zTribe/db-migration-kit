/** Safe child environment and fail-closed TAP result parsing for disposable PG17 tests. */
const SCRUB = [
 "DATABASE_URL","MIGRATION_DATABASE_URL","CHAT_MIGRATION_DATABASE_URL",
 "CHAT_MIGRATION_DATABASE_URL_DIRECT","CHAT_DATABASE_URL","CHAT_DB_URL",
 "INDEXER_DATABASE_URL","INDEXER_DATABASE_URL_DIRECT","INDEXER_TEST_DATABASE_URL",
 "INDEXER_UPGRADE_DATABASE_URL","CHAT_TEST_DATABASE_URL",
 "MAIN_MIGRATION_AUDIT_DATABASE_URL","SUPABASE_DB_URL","SUPABASE_DATABASE_URL",
 "PGHOST","PGHOSTADDR","PGPORT","PGUSER","PGPASSWORD","PGDATABASE",
 "PGSERVICE","PGSERVICEFILE","PGPASSFILE","PGSSLMODE","PGSSLCERT",
 "PGSSLKEY","PGSSLROOTCERT","MIGRATION_CANDIDATE_NAME","MIGRATION_CANDIDATE_CAPTURE",
 "MIGRATION_CANDIDATE_SQL","MIGRATION_PREPARE_CHECKS","MIGRATION_CANDIDATE_MODULE"
];
export function safeTestEnvironment(input,extras={}) {
  const safe={...input};
  for(const key of SCRUB)delete safe[key];
  return {...safe,...extras};
}
export function confirmTargetedFixtureRan(output,project) {
  const tests=/# tests\s+(\d+)\b/.exec(output);
  const passed=/# pass\s+(\d+)\b/.exec(output);
  const failed=/# fail\s+(\d+)\b/.exec(output);
  if(!tests||!passed||!failed||Number(tests[1])===0||
      Number(passed[1])===0||Number(failed[1])!==0)
    throw Error("Migration fixture for "+project+
      " did not execute and pass any targeted tests; check --test-name-pattern and skip guards");
}
