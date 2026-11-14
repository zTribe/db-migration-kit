import assert from "node:assert/strict";
import { loadMigrationConfig } from "./config.js";
import { loadManifest } from "./checksum.js";

/**
 * Run project-owned SQL contracts against Kit's validated migration manifest.
 * Keep project-specific security requirements in the project, not in Kit.
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
    let checked = 0;
    for (const [kind, patterns] of [["required", contract.required ?? []], ["forbidden", contract.forbidden ?? []]]) {
      if (!Array.isArray(patterns)) throw new TypeError(`${kind} must be an array`);
      for (const pattern of patterns) {
        if (!(pattern instanceof RegExp)) throw new TypeError(`${kind} entries must be RegExp`);
        if (kind === "required") assert.match(migration.sql, pattern, `${contract.version}: required ${pattern}`);
        else assert.doesNotMatch(migration.sql, pattern, `${contract.version}: forbidden ${pattern}`);
        checked++;
      }
    }
    results.push({ version: contract.version, checked });
  }
  return results;
}
