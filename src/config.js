import { generateMigrationSql } from "./migration-plan.js";
import { guardMigration } from "./guarded-plan.js";
import { readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { loadManifest } from "./checksum.js";

export async function loadMigrationConfig(path) {
  const config = JSON.parse(await readFile(path, "utf8"));
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new Error("Expected a migration configuration object");
  }
  for (const key of ["directory", "schema", "ledgerTable", "lockName", "targetState", "review"]) {
    if (key !== "directory" && config[key] === undefined) continue;
    if (typeof config[key] !== "string" || !config[key].trim() || config[key].includes("\0")) {
      throw new Error(`Invalid configuration field: ${key}`);
    }
  }
  const root = dirname(resolve(path));
  config.directory = resolve(root, config.directory);
  if (config.targetState) config.targetState = resolve(root, config.targetState);
  if (config.review) config.review = resolve(root, config.review);
  if (config.discovery !== undefined) {
    if (!["counter", "timestamp"].includes(config.discovery)) throw new Error("Invalid discovery mode");
    const prefix = config.discovery === "counter" ? /^\d{3}_[a-z0-9_]+\.sql$/ : /^\d{14}_[a-z0-9_]+\.sql$/;
    const entries = await readdir(config.directory);
    const sqlFiles = entries.filter(name => prefix.test(name));
    const files = sqlFiles.sort();
    if (config.files !== undefined) throw new Error("Specify files or discovery");
    config.files = files;
  }
  const manifest = await loadManifest(config);
  if (config.guard !== undefined) {
    const { version, before } = config.guard ?? {};
    if (!manifest.some(entry => entry.version === version) || typeof before !== "string" || !before.trim() ||
        !config.targetState || !config.review) throw new Error("Invalid guard configuration");
    const readJson = async file => JSON.parse(await readFile(file, "utf8"));
    const oldState = await readJson(resolve(root, before));
    const target = await readJson(config.targetState);
    const review = await readJson(config.review);
    const sql = generateMigrationSql(oldState, target, review);
    const guard = guardMigration(version, oldState, target, review);
    config.migrationGuard = {
      ...guard,
      async before(client, migration) {
        if (migration.sql.trim() !== sql.trim()) throw new Error("Migration SQL differs from reviewed plan");
        await guard.before(client);
      },
    };
  }
  return config;
}
