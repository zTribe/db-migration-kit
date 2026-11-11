import { qualifiedName } from "./identifiers.js";

/**
 * Verify a DB-controlled marker instead of guessing from a shared pooler host.
 * The marker must be provisioned by an administrator independently of the
 * migration runner. This function never creates or changes the marker.
 */
export async function verifyDatabaseTarget(client, expected) {
  if (!expected || !expected.projectRef || !expected.environment || !expected.schema || !expected.table) {
    throw new Error("database target identity requires schema, table, projectRef and environment");
  }
  if (!/^[a-z0-9_-]{6,128}$/i.test(expected.projectRef)) throw new Error("invalid expected projectRef");
  if (!["dev", "production", "test"].includes(expected.environment)) throw new Error("invalid expected database environment");
  const tableName = qualifiedName(expected.schema, expected.table);
  const { rows } = await client.query(
    `SELECT project_ref, environment FROM ${tableName} WHERE singleton = true`,
  );
  if (rows.length !== 1 ||
      rows[0].project_ref !== expected.projectRef ||
      rows[0].environment !== expected.environment) {
    throw new Error("database target identity mismatch; migration blocked");
  }
  return { verified: true, environment: expected.environment };
}
