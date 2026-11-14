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

