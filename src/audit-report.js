/** Stable report boundary shared by CLI, migration hooks and service adapters. */
export function buildSecurityAudit(snapshot, rules, failures) {
  const diagnostics = failures.map((message, index) => ({
    code: "RUNTIME_SECURITY_POLICY_VIOLATION",
    id: `security_${String(index+1).padStart(3,"0")}`,
    severity: "error",
    message,
  }));
  return {
    ok: diagnostics.length === 0,
    failures: [...failures],
    diagnostics,
    // Keep historic consumers compatible while exposing the richer fact snapshot.
    snapshot,
    summary: {
      schemas: snapshot.schemas.length,
      tables: snapshot.tables.length,
      functions: snapshot.functions.length,
      roles: snapshot.roles.length,
      errors: diagnostics.length,
    },
  };
}
