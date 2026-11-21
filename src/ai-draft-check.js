import { checksumText } from "./checksum.js";
import { assertManagedTransaction } from "./transaction-sql.js";
import { createOwnerMaintenancePolicy, structuralSql } from "./owner-maintenance.js";
import { analyzeMigrationSqlAst } from "./migration-sql-ast.js";

/**
 * AI-facing early feedback only. Does not connect to a database or approve a release.
 * All findings must be followed by the actual PG17 non-superuser upgrade.
 */
export async function checkAiMigrationDraft({name, sql, ownerConfig, analyzer = analyzeMigrationSqlAst}) {
  const issues = [];
  const add = (severity, code, message, next) => issues.push({severity, code, message, next});
  if(typeof name !== "string" || !/^[a-z][a-z0-9_]*$/.test(name))
    add("error", "NAME_INVALID", "Migration name must be lowercase snake_case.",
      "Use a semantic name without a version prefix; Kit chooses the next version.");
  if(typeof sql !== "string" || !sql.trim())
    return {ok:false, releaseApproved:false, sqlChecksum:null, touches:[],
      issues:[...issues,{severity:"error",code:"SQL_EMPTY",message:"Candidate SQL is empty.",next:"Write a candidate first."}]};
  const normalized = sql.trimEnd() + "\n";
  let structural = "";
  try {
    assertManagedTransaction(normalized, name);
    structural = structuralSql(normalized);
  } catch(error) {
    add("error", "SQL_LEXICAL_OR_TRANSACTION", String(error.message ?? error),
      "Leave transaction control to Kit; fix unclosed SQL literals/comments.");
  }
  try {
    const policy = createOwnerMaintenancePolicy(ownerConfig);
    policy.forCandidate(name,normalized);
  } catch(error) {
    add("error", "OWNER_POLICY", String(error.message ?? error),
      "Prefer a new versioned RPC, or request a scoped, reviewed Owner recipe. Never grant permanent runtime privileges.");
  }
  if(structural) {
    if(/\bcreate\s+(?:unique\s+)?index\s+concurrently\b/i.test(structural))
      add("error","CONCURRENT_INDEX","Guarded transactional migrations cannot CREATE INDEX CONCURRENTLY.",
        "Use an explicitly reviewed nontransactional migration workflow.");
    for(const statement of structural.split(";")) {
      if(/\bsecurity\s+definer\b/i.test(statement) &&
          !/\bset\s+search_path\s*(?:=|to)\s*/i.test(statement))
        add("error","DEFINER_PATH","Each SECURITY DEFINER statement needs its own fixed search_path.",
          "Add an explicit trusted search_path to this statement and verify caller permissions and pg_temp isolation in PG17.");
    }
    if(/\b(?:create\s+or\s+replace|alter|drop)\s+function\b/i.test(structural))
      add("review","FUNCTION_OWNER","Function DDL may require privileges held by an existing owner.",
        "Inspect function signature, owner, schema CREATE and role SET/ADMIN privileges in the PG17 fixture.");
    if(/(?:^|;)\s*(?:do|call)\b/im.test(structural))
      add("review","DYNAMIC_SQL","Dynamic SQL or procedure calls prevent complete static capability verification.",
        "Review the exact DO/CALL body, affected objects and owner/RLS rights; add real PG17 negative and positive assertions.");
    if(/\b(?:drop\s+(?:table|schema)|truncate\s+table|delete\s+from)\b/i.test(structural))
      add("review","DATA_CHANGE","Destructive or bulk data changes require explicit review.",
        "Review locks, data retention, backup, compatibility and rollback/compensation.");
  }
  let touches=[];
  if(structural) {
    try {
      const parsed=await analyzer(normalized);
      touches=parsed.touches ?? [];
      if(parsed.uncertain) add("review","AST_UNCERTAIN",(parsed.warnings??[]).join("; "),
        "Inspect dependency graph and role effects; confirm with PostgreSQL 17.");
    } catch(error) {
      add("review","AST_PARSE_UNCERTAIN",String(error.message ?? error),
        "Parser may differ from PostgreSQL 17; do not change valid PG17 SQL solely to satisfy the advisory parser.");
    }
  }
  return {ok:!issues.some(x=>x.severity==="error"),releaseApproved:false,
    sqlChecksum:checksumText(normalized),touches,issues};
}
