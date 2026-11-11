import { loadManifest } from "./checksum.js";
import { qualifiedName, quoteIdentifier } from "./identifiers.js";
import { withMigrationLock } from "./lock.js";
import { hardenMigrationLedger } from "./ledger-security.js";
import { autoBaselineVerifiedCatalog } from "./auto-baseline.js";

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

function compareLedger(rows, migrations, config = {}) {
  const byVersion = new Map(rows.map(row => [row.version, row]));
  const expected = new Map(migrations.map(item => [item.version, item]));
  const unknown = rows.filter(row => !expected.has(row.version));
  const drift = rows.filter(row => {
    const item = expected.get(row.version);
    if (!item) return false;
    if (row.name !== item.name) return true;
    if (row.source === "baseline") {
      const legacy = config.legacyBaselineChecksums?.[row.version];
      if (legacy) {
        return row.checksum !== legacy.ledgerChecksum ||
          item.checksum !== legacy.sqlChecksum;
      }
    }
    return row.checksum !== item.checksum;
  });
  const pending = migrations.filter(item => !byVersion.has(item.version));
  const invalidSources = rows.filter(row => row.source !== "baseline" && row.source !== "migration");
  return { applied: rows, pending, unknown, drift, invalidSources, ok: unknown.length === 0 && drift.length === 0 && invalidSources.length === 0 };
}

export async function inspectMigrations(pool, options) {
  const config = { ...DEFAULTS, ...options };
  const migrations = await loadManifest(config);
  const client = await pool.connect();
  try {
    return compareLedger(await readLedger(client, config.schema, config.ledgerTable), migrations, config);
  } finally {
    client.release();
  }
}

export async function applyMigrations(pool, options) {
  const config = { ...DEFAULTS, ...options };
  const migrations = await loadManifest(config);
  const appliedNow = [];
  return withMigrationLock(pool, config, async client => {
    const preflight = compareLedger(await readLedger(client, config.schema, config.ledgerTable), migrations, config);
    if (preflight.unknown.length) throw new Error(`unknown applied migration(s): ${preflight.unknown.map(row => row.version).join(", ")}; refusing writes`);
    if (preflight.drift.length) throw new Error(`checksum/name mismatch for applied migration(s): ${preflight.drift.map(row => row.version).join(", ")}; refusing writes`);
    if (preflight.invalidSources.length) throw new Error("invalid ledger source; refusing writes");
    if (typeof config.verifyTarget === "function") await config.verifyTarget(client, config);
    // Make ledger creation and optional ACL hardening atomic: no exposure
    // window for a newly created ledger.
    await client.query("BEGIN");
    try {
      await ensureLedger(client, config.schema, config.ledgerTable);
      if(config.ledgerSecurity) await hardenMigrationLedger(client, {...config, ...config.ledgerSecurity});
      await client.query("COMMIT");
    } catch(error) {
      await client.query("ROLLBACK").catch(()=>undefined);
      throw error;
    }
    if(config.autoBaseline) await autoBaselineVerifiedCatalog(client, config, migrations);
    if (typeof config.beforeMigrations === "function") await config.beforeMigrations(client, config);
    const rows = await readLedger(client, config.schema, config.ledgerTable);
    const report = compareLedger(rows, migrations, config);
    if (report.unknown.length) throw new Error(`database contains unknown migration(s): ${report.unknown.map(x=>x.version).join(", ")}`);
    if (report.drift.length) throw new Error(`checksum/name mismatch for applied migration(s): ${report.drift.map(x=>x.version).join(", ")}; create a new migration instead of editing history`);
    if (report.invalidSources.length) throw new Error("migration ledger contains invalid source values");
    const byVersion = new Set(rows.map(row => row.version));
    for (const migration of migrations) {
      if (byVersion.has(migration.version)) continue;
      const nonTransactional = /^--[ \t]*migrate:non-transactional(?:-index)?[ \t]*$/mi.test(migration.sql);
      if (nonTransactional) {
        if (config.allowNonTransactional !== true) throw new Error(`non-transactional migration ${migration.version} requires explicit allowNonTransactional=true; partial execution cannot be rolled back`);
        if (typeof config.beforeMigration === "function") await config.beforeMigration(client, migration, config);
        await client.query(migration.sql);
        await client.query(
          `INSERT INTO ${qualifiedName(config.schema, config.ledgerTable)} (version,name,checksum,source) VALUES ($1,$2,$3,'migration')`,
          [migration.version, migration.name, migration.checksum],
        );
      } else {
        await client.query("BEGIN");
        try {
          if (typeof config.beforeMigration === "function") await config.beforeMigration(client, migration, config);
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
  });
}

/**
 * One baseline mechanism for service adapters. The adapter must independently
 * prove the live catalog corresponds to the declared baseline target.
 * No SQL migration is executed during baseline registration.
 */
export async function baselineMigrations(pool, options) {
  const config = { ...DEFAULTS, ...options };
  if (typeof config.verifyBaseline !== "function") throw new Error("baseline requires verifyBaseline live catalog proof");
  if (typeof config.baselineThrough !== "string" || !config.baselineThrough) throw new Error("baselineThrough is required");
  const migrations = await loadManifest(config);
  const lastIndex = migrations.findIndex(item => item.version === config.baselineThrough);
  if (lastIndex < 0) throw new Error("baselineThrough is not in the migration manifest");
  return withMigrationLock(pool, config, async client => {
    if (typeof config.verifyTarget === "function") await config.verifyTarget(client, config);
    const previous = compareLedger(await readLedger(client, config.schema, config.ledgerTable), migrations, config);
    if (!previous.ok) throw new Error("baseline refused due to unknown migrations or checksum drift");
    const expectedPrefix = new Set(migrations.slice(0, lastIndex + 1).map(x => x.version));
    if (previous.applied.some(x => !expectedPrefix.has(x.version))) throw new Error("baseline refused: migrations already recorded after baselineThrough");
    const verified = await config.verifyBaseline(client, { through: config.baselineThrough, migrations, applied: previous.applied });
    if (verified !== true) throw new Error("baseline refused: live catalog does not match declared baseline");
    await client.query("BEGIN");
    try {
      await ensureLedger(client, config.schema, config.ledgerTable);
      if(config.ledgerSecurity) await hardenMigrationLedger(client, {...config, ...config.ledgerSecurity});
      const already = new Set(previous.applied.map(x => x.version));
      const recorded = [];
      for (const migration of migrations.slice(0, lastIndex + 1)) {
        if (already.has(migration.version)) continue;
        await client.query(
          `INSERT INTO ${qualifiedName(config.schema, config.ledgerTable)} (version,name,checksum,source) VALUES ($1,$2,$3,'baseline')`,
          [migration.version, migration.name, migration.checksum],
        );
        recorded.push(migration.version);
      }
      await client.query("COMMIT");
      return { recorded, through: config.baselineThrough };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    }
  });
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
    const report = compareLedger(await readLedger(client, config.schema, config.ledgerTable), migrations, config);
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
