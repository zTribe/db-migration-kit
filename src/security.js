import { SECURITY_CATALOG_SQL, collectSecurityCatalog } from "./catalog.js";
import { evaluateSecurityPolicy } from "./policy.js";
import { buildSecurityAudit } from "./audit-report.js";

// Backward-compatible entrypoint: existing Indexer/Chat callers keep working.
export { SECURITY_CATALOG_SQL };
export async function inspectRuntimeSecurity(pool, rules = {}) {
  const snapshot = await collectSecurityCatalog(pool, rules);
  return buildSecurityAudit(snapshot, rules, evaluateSecurityPolicy(snapshot, rules));
}
