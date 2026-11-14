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
  await loadManifest(config);
  return config;
}
