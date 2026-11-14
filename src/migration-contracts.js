import assert from "node:assert/strict";
import { loadMigrationConfig } from "./config.js";
import { loadManifest } from "./checksum.js";

/**
 * Validate project-owned SQL contracts without teaching Kit project-specific SQL.
 * A contract describes expected/forbidden patterns for one migration version.
 */
export async function verifyMigrationContracts(configPath, contracts) {
  if (!Array.isArray(contracts)) throw new TypeError("contracts must be an array");
  const config = await loadMigrationConfig(configPath);
  const manifest = await loadManifest(config);
  const byVersion = new Map(manifest.map(entry => [entry.version, entry]));
  const results = [];
  for (const contract of contracts) {
    if (!contract || typeof contract.version !== "string" || !contract.version) {
      throw new TypeError("contract.version must be a non-empty string");
    }
    const migration = byVersion.get(contract.version);
    assert.ok(migration, `migration missing: ${contract.version}`);
    for (const [kind, patterns] of [["required", contract.required ?? []], ["forbidden", contract.forbidden ?? []]]) {
      if (!Array.isArray(patterns)) throw new TypeError(`${kind} must be an array`);
      for (const pattern of patterns) {
        if (!(pattern instanceof RegExp)) throw new TypeError(`${kind} entries must be RegExp`);
        if (kind === "required") assert.match(migration.sql, pattern, `${contract.version}: required ${pattern}`);
        else assert.doesNotMatch(migration.sql, pattern, `${contract.version}: forbidden ${pattern}`);
      }
    }
    results.push({ version: contract.version, checked: (contract.required?.length ?? 0) + (contract.forbidden?.length ?? 0) });
  }
  return results;
}
