import { loadManifest } from "./checksum.js";
import { qualifiedName, quoteIdentifier } from "./identifiers.js";

const DEFAULTS = {
  schema: "public",
  ledgerTable: "schema_migrations",
  lockName: "ztribe-shared-schema-migrations",
};

async function ensureLedger(client, schema, table) {
  const q = qualifiedName(schema, table);
  await client.query(`CREATE SCHEMA IF NOT EXISTS ${quoteIdentifier(schema)}`);
  await client.query(`
    CREATE TABLE IF NOT EXISTS ${q} (
      version text PRIMARY KEY,
      name text NOT NULL,
      checksum text NOT NULL,
      source text NOT NULL CHECK (source IN ('migration','baseline')),
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);
}

async function readLedger(client, schema, table) {
  const exists = await client.query("SELECT pg_catalog.to_regclass($1) IS NOT NULL AS exists", [`${quoteIdentifier(schema)}.${quoteIdentifier(table)}`]);
  if (!exists.rows[0]?.exists) return [];
  const result = await client.query(`SELECT version,name,checksum,source,applied_at FROM ${qualifiedName(schema, table)} ORDER BY version`);
  return result.rows;
}

function compareLedger(rows, migrations) {
  const byVersion = new Map(rows.map(row => [row.version, row]));
  const expected = new Map(migrations.map(item => [item.version, item]));
  const unknown = rows.filter(row => !expected.has(row.version));
  const drift = rows.filter(row => {
    const item = expected.get(row.version);
    return item && row.source !== "baseline" && (row.name !== item.name || row.checksum !== item.checksum);
  });
  const pending = migrations.filter(item => !byVersion.has(item.version));
  return { applied: rows, pending, unknown, drift, ok: unknown.length === 0 && drift.length === 0 };
}

export async function inspectMigrations(pool, options) {
  const config = { ...DEFAULTS, ...options };
  const migrations = await loadManifest(config);
  const client = await pool.connect();
  try {
    return compareLedger(await readLedger(client, config.schema, config.ledgerTable), migrations);
  } finally {
    client.release();
  }
}

export async function applyMigrations(pool, options) {
  const config = { ...DEFAULTS, ...options };
  const migrations = await loadManifest(config);
  const client = await pool.connect();
  let locked = false;
  const appliedNow = [];
  try {
    await client.query("SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended($1,0))", [config.lockName]);
    locked = true;
    await ensureLedger(client, config.schema, config.ledgerTable);
    if (typeof config.beforeMigrations === "function") await config.beforeMigrations(client, config);
    const rows = await readLedger(client, config.schema, config.ledgerTable);
    const report = compareLedger(rows, migrations);
    if (report.unknown.length) throw new Error(`database contains unknown migration(s): ${report.unknown.map(x=>x.version).join(", ")}`);
    if (report.drift.length) throw new Error(`checksum/name mismatch for applied migration(s): ${report.drift.map(x=>x.version).join(", ")}; create a new migration instead of editing history`);
    const byVersion = new Set(rows.map(row => row.version));
    for (const migration of migrations) {
      if (byVersion.has(migration.version)) continue;
      const nonTransactional = /^--\s*migrate:non-transactional\s*$/mi.test(migration.sql);
      if (nonTransactional) {
        await client.query(migration.sql);
        await client.query(
          `INSERT INTO ${qualifiedName(config.schema, config.ledgerTable)} (version,name,checksum,source) VALUES ($1,$2,$3,'migration')`,
          [migration.version, migration.name, migration.checksum],
        );
      } else {
        await client.query("BEGIN");
        try {
          await client.query(migration.sql);
          await client.query(
            `INSERT INTO ${qualifiedName(config.schema, config.ledgerTable)} (version,name,checksum,source) VALUES ($1,$2,$3,'migration')`,
            [migration.version, migration.name, migration.checksum],
          );
          await client.query("COMMIT");
        } catch (error) {
          await client.query("ROLLBACK").catch(() => undefined);
          throw error;
        }
      }
      appliedNow.push(migration.version);
      byVersion.add(migration.version);
    }
    return { applied: appliedNow, total: migrations.length };
  } finally {
    if (locked) {
      await client.query("SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended($1,0))", [config.lockName]).catch(() => undefined);
    }
    client.release();
  }
}

export async function auditMigrations(pool, options) {
  const config = { ...DEFAULTS, ...options };
  const migrations = await loadManifest(config);
  const client = await pool.connect();
  let inTransaction = false;
  try {
    await client.query("BEGIN READ ONLY");
    inTransaction = true;
    await client.query("SET LOCAL statement_timeout='10s'");
    await client.query("SET LOCAL lock_timeout='3s'");
    const report = compareLedger(await readLedger(client, config.schema, config.ledgerTable), migrations);
    await client.query("COMMIT");
    inTransaction = false;
    if (!report.ok) throw Object.assign(new Error("migration audit failed: unknown versions or checksum drift"), { report });
    return report;
  } catch (error) {
    if (inTransaction) await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
