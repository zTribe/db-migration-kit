/** Stable report boundary shared by CLI, migration hooks and service adapters. */
export function buildSecurityAudit(snapshot, rules, failures, objectViolations = []) {
  const diagnostics = failures.map((message, index) => ({
    code: "RUNTIME_SECURITY_POLICY_VIOLATION",
    id: `security_${String(index+1).padStart(3,"0")}`,
    severity: "error",
    message,
  }));
  const start=failures.length-objectViolations.length;
  for(let index=0;index<objectViolations.length;index++) {
    const violation=objectViolations[index];
    diagnostics[start+index]={
      id:diagnostics[start+index].id, severity:"error", ...violation,
    };
  }
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
      columns: (snapshot.columns ?? []).length,
      sequences: (snapshot.sequences ?? []).length,
      policies: (snapshot.policies ?? []).length,
      errors: diagnostics.length,
    },
  };
}
