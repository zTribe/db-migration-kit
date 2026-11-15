import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { analyzeMigrationSqlAst } from "./migration-sql-ast.js";
import { checksumText } from "./checksum.js";

/**
 * Audit every versioned migration without modifying either the SQL or its ledger.
 * PostgreSQL 18 parser mismatches against PostgreSQL 17 migrations are evidence,
 * not permission to change immutable historical SQL.
 *
 * Parser failure does not imply the PostgreSQL 17 migration is invalid. All
 * failures and uncertain AST findings remain unapproved and visible in JSON.
 */
export async function scanMigrationHistoryAst(config, options = {}) {
  if (!Array.isArray(config?.files) || !config.files.length ||
      typeof config.directory !== "string" || !config.directory) {
    throw new Error("Historical AST scan requires a validated migration config");
  }
  const files = [...config.files].sort();
  const changed = new Set(options.changedFiles ?? []);
  const findings = [];
  for (const file of files) {
    if (!/^[a-z0-9_]+\.sql$/i.test(file)) throw new Error("Invalid migration filename: " + file);
    const sql = await readFile(resolve(config.directory, file), "utf8");
    const checksum = checksumText(sql);
    const isChanged = changed.has(file) || changed.has("db/migrations/" + file);
    try {
      const analysis = await analyzeMigrationSqlAst(sql);
      findings.push({
        file, checksum, changed:isChanged, status:analysis.uncertain ? "review-required" : "parsed",
        touches:analysis.touches, warnings:analysis.warnings, parserError:null,
      });
    } catch (error) {
      findings.push({
        file, checksum, changed:isChanged, status:"parse-error", touches:[],
        warnings:["postgresql-ast-parse-failed"],
        parserError:String(error?.message ?? error).slice(0,600),
      });
    }
  }
  const summary = {
    files:findings.length,
    parsed:findings.filter(x=>x.status==="parsed").length,
    reviewRequired:findings.filter(x=>x.status==="review-required").length,
    parseErrors:findings.filter(x=>x.status==="parse-error").length,
    changed:findings.filter(x=>x.changed).length,
    changedParseErrors:findings.filter(x=>x.changed && x.status==="parse-error").length,
  };
  return {
    version:1, analysis:"postgresql-ast-history", parserFamily:"libpg-query",
    parserMajor:18, targetPostgresMajor:17, releaseApproved:false,
    dependencyGraphComplete:false, summary, findings,
    warnings:[
      "Static AST findings never approve a database or Redis release.",
      "PostgreSQL 18 parser failure is not proof of invalid PostgreSQL 17 SQL.",
      "Use actual PG17 historical replay, upgrades, permissions and dependency review as authoritative gates.",
    ],
  };
}
