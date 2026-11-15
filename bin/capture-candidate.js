import { readFile, writeFile } from "node:fs/promises";
import { normalizeMigrationRole, planMigration, readTargetState } from "../src/index.js";
import { assertManagedTransaction } from "../src/transaction-sql.js";

// Called by a consumer's upgrade fixture after provisioning its migration role.
export async function captureCandidate(migrator, schemas) {
  const { MIGRATION_CANDIDATE_SQL: source, MIGRATION_CANDIDATE_CAPTURE: output } = process.env;
  const sql = await readFile(source, "utf8");
  assertManagedTransaction(sql, source);
  const client = await migrator.connect();
  try {
    await client.query("BEGIN");
    const { rows: [role] } = await client.query(`
      SELECT rolname, rolsuper, rolbypassrls,
        current_setting('server_version_num')::int / 10000 AS major
      FROM pg_roles WHERE rolname = current_user
    `);
    if (role.rolsuper || role.rolbypassrls || role.major !== 17) {
      throw new Error("Candidate capture requires a non-superuser, non-BYPASSRLS PostgreSQL 17 migration role");
    }
    const capture = async () => normalizeMigrationRole(await readTargetState(client, schemas), role.rolname);
    const before = await capture();
    await client.query(sql);
    const after = await capture();
    const plan = planMigration(before, after);
    if (!plan.structure.length && !plan.changes.length) {
      throw new Error("Candidate produced no catalog changes. Use the project's explicit review workflow for data-only migrations.");
    }
    await writeFile(output, JSON.stringify({ before, after, digest: plan.digest }), { flag: "wx" });
  } finally {
    try { await client.query("ROLLBACK"); }
    finally { client.release(); }
  }
}
