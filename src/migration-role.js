export const MIGRATION_ROLE = "@migration-role";

export function normalizeMigrationRole(state, role) {
  const result = structuredClone(state);
  const rename = name => name === role ? MIGRATION_ROLE : name;
  const escaped = role.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const aclRole = new RegExp(`(^|[,{"/])${escaped}(?=["=,}]|$)`, "g");
  const acl = value => value.replace(aclRole, (_, prefix) => prefix + MIGRATION_ROLE);
  for (const rows of Object.values(result.permissions)) {
    for (const row of rows) {
      for (const field of ["owner", "rolname", "member", "parent"]) {
        if (field in row) row[field] = rename(row[field]);
      }
      if (typeof row.acl === "string") row.acl = acl(row.acl);
      if (Array.isArray(row.acl)) row.acl = row.acl.map(acl).sort();
      if (Array.isArray(row.roles)) row.roles = row.roles.map(rename).sort();
    }
  }
  for (const policy of result.schema?.policies ?? []) policy.roles = policy.roles.map(rename).sort();
  result.migrationRole = MIGRATION_ROLE;
  return result;
}
