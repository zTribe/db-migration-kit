/**
 * Single-session, bounded PostgreSQL advisory lock used by all write paths.
 * A session-pooling connection (not transaction pooling) is required.
 */
export async function withMigrationLock(pool, options, work) {
  const { lockName, lockWaitMs = 30000, lockPollMs = 100 } = options;
  if (typeof lockName !== "string" || !lockName) throw new Error("migration lockName is required");
  if (!Number.isSafeInteger(lockWaitMs) || lockWaitMs < 0 ||
      !Number.isSafeInteger(lockPollMs) || lockPollMs < 1) throw new Error("invalid migration lock timing");
  const client = await pool.connect();
  let held = false;
  const started = Date.now();
  try {
    do {
      const result = await client.query(
        "SELECT pg_catalog.pg_try_advisory_lock(pg_catalog.hashtextextended($1,0)) AS locked",
        [lockName],
      );
      held = result.rows[0]?.locked === true;
      if (held) break;
      if (Date.now() - started >= lockWaitMs) {
        throw new Error("migration advisory lock timeout: another migration process may be running");
      }
      await new Promise(resolve => setTimeout(resolve, Math.min(lockPollMs, lockWaitMs)));
    } while (!held);
    return await work(client);
  } finally {
    if (held) {
      await client.query(
        "SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended($1,0))",
        [lockName],
      ).catch(() => undefined);
    }
    client.release();
  }
}
