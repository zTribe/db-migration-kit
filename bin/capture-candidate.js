import { readFile, writeFile } from "node:fs/promises";
import { normalizeMigrationRole, planMigration, readTargetState } from "../src/index.js";
import { assertManagedTransaction } from "../src/transaction-sql.js";
import { createOwnerMaintenancePolicy, acquireTemporaryOwnerRole, releaseTemporaryOwnerRole } from "../src/owner-maintenance.js";
import { preflightMigrationCapabilities } from "../src/capability.js";
import { preflightRelationCapabilities } from "../src/relation-capability.js";
import { resolve } from "node:path";

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
    const name = process.env.MIGRATION_CANDIDATE_NAME;
    if (!name) throw Error("Candidate migration name missing; use the Kit prepare command");
    const policy = createOwnerMaintenancePolicy(JSON.parse(
      await readFile(resolve("db/owner-maintenance-policy.json"),"utf8")));
    const recipe = policy.forCandidate(name,sql);
    const lease = recipe ? await acquireTemporaryOwnerRole(client,recipe) : null;
    try {
      await preflightMigrationCapabilities(client,sql,{future:true});
      await preflightRelationCapabilities(client,sql);
      await client.query(sql);
      if(lease)await releaseTemporaryOwnerRole(client,lease);
    } catch(error) {
      // Outer transaction rolls back any role grant and DDL together.
      throw error;
    }
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

// The fixture runs this after the service's own upgrade assertions.
export async function verifyCandidateChecks(pool, path) {
  const sql = await readFile(path, "utf8");
  assertManagedTransaction(sql, path);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL statement_timeout = '10s'");
    const result = await client.query(sql);
    const rows = (Array.isArray(result) ? result.at(-1) : result)?.rows;
    if (!rows?.length || rows.some(row =>
      typeof row.check_name !== "string" || !row.check_name.trim() || typeof row.passed !== "boolean"
    ) || new Set(rows.map(row => row.check_name)).size !== rows.length) {
      throw new Error("checks.sql must end with unique, nonempty check_name text and passed boolean rows");
    }
    const failures = rows.filter(row => !row.passed).map(row => row.check_name);
    if (failures.length) throw new Error(`Migration assertions failed: ${failures.join(", ")}`);
    console.log(`Migration assertions passed (${rows.length}): ${rows.map(row => row.check_name).join(", ")}`);
  } finally {
    try { await client.query("ROLLBACK"); }
    finally { client.release(); }
  }
}
