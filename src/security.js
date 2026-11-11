import { SECURITY_CATALOG_SQL, collectSecurityCatalog } from "./catalog.js";
import { evaluateSecurityPolicy } from "./policy.js";
import { buildSecurityAudit } from "./audit-report.js";
import { evaluateObjectPolicies } from "./object-policy.js";

// Backward-compatible entrypoint: existing Indexer/Chat callers keep working.
export { SECURITY_CATALOG_SQL };
export async function inspectRuntimeSecurity(pool, rules = {}) {
  const snapshot = await collectSecurityCatalog(pool, rules);
  const legacyFailures = evaluateSecurityPolicy(snapshot, rules);
  const objectViolations = evaluateObjectPolicies(snapshot, rules);
  return buildSecurityAudit(snapshot, rules,
    [...legacyFailures, ...objectViolations.map(issue => issue.message)],
    objectViolations);
}
