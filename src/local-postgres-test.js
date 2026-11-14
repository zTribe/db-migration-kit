import pg from "pg";

/** Test-only safety boundary. This module is never imported by the production entrypoint. */
export function assertLocalTestDatabase(databaseUrl) {
  if (typeof databaseUrl !== "string" || !databaseUrl) throw new Error("Local test database URL is required");
  let parsed;
  try { parsed = new URL(databaseUrl); } catch { throw new Error("Invalid local test database URL"); }
  if (!["postgresql:", "postgres:"].includes(parsed.protocol) ||
      !["127.0.0.1", "localhost", "::1", "[::1]"].includes(parsed.hostname)) {
    throw new Error("Integration tests may connect only to loopback PostgreSQL");
  }
  return parsed;
}

/**
 * Open an explicitly local PostgreSQL test connection and always close it.
 * Schema setup/reset remains an explicit project callback; never auto-drop databases.
 */
export async function withLocalPostgres(databaseUrl, run, { max = 4 } = {}) {
  assertLocalTestDatabase(databaseUrl);
  if (typeof run !== "function") throw new TypeError("run must be a function");
  const pool = new pg.Pool({ connectionString: databaseUrl, max });
  try { return await run(pool); }
  finally { await pool.end(); }
}
