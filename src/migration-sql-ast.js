import { parse } from "libpg-query";

/**
 * Conservative PostgreSQL-AST migration touch extraction.
 *
 * This is an advisory preflight, NOT a replacement for replay, catalog diff,
 * migration policy approval, or PostgreSQL 17 execution. Unknown, dynamic,
 * unqualified and potentially indirect operations always request review.
 */
export async function analyzeMigrationSqlAst(sql) {
  if (typeof sql !== "string" || !sql.trim()) throw new Error("Migration SQL required");
  // A parse error is a hard failure, not an empty dependency report.
  const ast = await parse(sql);
  if (!Array.isArray(ast?.stmts) || ast.stmts.length === 0)
    throw new Error("PostgreSQL AST returned no statements");
  const touches = [];
  const warnings = new Set();
  const touched = new Set();
  const namePart = x => x?.String?.sval ?? x?.String?.str ?? x?.sval ?? null;
  function record(kind, name, reason) {
    if (typeof name !== "string" || !/^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/i.test(name) ||
        name !== name.toLowerCase()) {
      warnings.add("unresolved-or-case-sensitive-identifier:" + String(name));
      return;
    }
    const key = kind + ":" + name;
    if (!touched.has(key)) { touched.add(key); touches.push({kind, name, reason}); }
  }
  function relation(rel, reason) {
    if (!rel || typeof rel.relname !== "string" || typeof rel.schemaname !== "string") {
      warnings.add("unqualified-or-unsupported-relation");
      return;
    }
    record("table", rel.schemaname + "." + rel.relname, reason);
  }
  function functionName(parts, reason) {
    if (!Array.isArray(parts) || parts.length !== 2) {
      warnings.add("unqualified-or-unsupported-function");
      return;
    }
    record("function", parts.map(namePart).join("."), reason);
  }
  for (const entry of ast.stmts) {
    const stmt = entry?.stmt;
    const kinds = stmt && typeof stmt === "object" ? Object.keys(stmt) : [];
    if (kinds.length !== 1) { warnings.add("unknown-statement-node"); continue; }
    const kind = kinds[0], node = stmt[kind];
    switch (kind) {
      case "AlterTableStmt":
      case "CreateStmt":
        relation(node?.relation, "ast:" + kind);
        break;
      case "IndexStmt":
        relation(node?.relation, "ast:IndexStmt");
        break;
      case "InsertStmt":
      case "UpdateStmt":
      case "DeleteStmt":
      case "MergeStmt":
        relation(node?.relation, "ast:" + kind);
        // Only write targets are touched; source relations are not mutated.
        break;
      case "CreateFunctionStmt":
        functionName(node?.funcname, "ast:CreateFunctionStmt");
        // Body can include DML, dynamic SQL, security-definer calls, etc.
        warnings.add("function-body-requires-catalog-and-dependency-review");
        break;
      case "DropStmt":
      case "GrantStmt":
      case "DoStmt":
      case "ViewStmt":
      case "CreateTrigStmt":
      case "AlterFunctionStmt":
      case "RenameStmt":
      case "CommentStmt":
      case "CreateSchemaStmt":
        warnings.add("indirect-or-complex-statement:" + kind);
        break;
      default:
        // Never silently approve a statement not covered by this extractor.
        warnings.add("unsupported-statement:" + kind);
    }
  }
  return {touches, uncertain:warnings.size > 0, warnings:[...warnings].sort(),
    parserFamily:"libpg-query", releaseApproved:false};
}
