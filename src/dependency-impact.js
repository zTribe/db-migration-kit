import { checksumText } from "./checksum.js";

/**
 * Generic migration dependency impact planner.
 * Project-specific dependency manifests live with each consumer, never in Kit.
 * Inputs may come from planMigration() or a reviewed explicit SQL migration.
 * This is a review/CI signal; it does not execute DDL or invalidate caches.
 */
const normalize = value => String(value ?? "").trim().toLowerCase().replaceAll('"', "");
const fullName = name => normalize(name).replace(/\s+/g, "");
function validateRules(rules) {
  if (!Array.isArray(rules)) throw new Error("Dependency rules must be an array");
  const ids = new Set();
  for (const rule of rules) {
    if (!rule || typeof rule.id !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/.test(rule.id) ||
        ids.has(rule.id) || !Array.isArray(rule.sources) || !rule.sources.length ||
        !["cache", "security", "other"].includes(rule.kind)) throw new Error("Invalid dependency rule");
    ids.add(rule.id);
    for (const source of rule.sources) {
      if (!source || !["table", "column", "function"].includes(source.kind) ||
          typeof source.name !== "string" || !/^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?$/.test(source.name)) {
        throw new Error("Invalid dependency source");
      }
    }
  }
}
function makeTouch(kind, name, reason) { return { kind, name: fullName(name), reason }; }
function extractPlanTouches(plan) {
  const touches = [];
  if (!plan) return touches;
  for (const change of plan.changes ?? []) {
    const name = (change.identity ?? []).join(".");
    if (change.section === "functions") touches.push(makeTouch("function", name, "permission/function diff"));
    if (change.section === "objects") touches.push(makeTouch("table", name, "table permission diff"));
    if (change.section === "columnPrivileges") touches.push(makeTouch("column",name,"column privilege diff"));
  }
  for (const change of plan.structure ?? []) {
    const name = change.key ?? "";
    if (change.section === "functions") touches.push(makeTouch("function",name,"function schema diff"));
    if (change.section === "columns") touches.push(makeTouch("column",name,"column schema diff"));
    if (change.section === "tables") touches.push(makeTouch("table",name,"table schema diff"));
  }
  return touches;
}
function extractSqlTouches(sql) {
  if (typeof sql !== "string") throw new Error("SQL input must be a string");
  // Signal only: SQL may contain dynamic EXECUTE, functions and data changes.
  // Unparseable or data-changing SQL needs explicit review rather than a silent OK.
  const statements = sql.replace(/--[^\n]*/g, "").split(";").filter(s => s.trim());
  const touches = [];
  const patterns = [
    ["table", /\b(?:ALTER|CREATE|DROP|TRUNCATE)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?([\w".]+)|\b(?:UPDATE|INSERT\s+INTO|DELETE\s+FROM)\s+([\w".]+)/gi],
    ["function", /\b(?:CREATE\s+(?:OR\s+REPLACE\s+)?|ALTER\s+|DROP\s+)FUNCTION\s+([\w".]+)/gi],
  ];
  for (const statement of statements) for (const [kind, pattern] of patterns) {
    for (const match of statement.matchAll(pattern)) {
      const name = match[1] ?? match[2];
      if (name?.includes(".")) touches.push(makeTouch(kind,name,"explicit SQL"));
    }
  }
  const uncertain = /\b(EXECUTE|DO\s+\$|CALL\b|REFRESH\s+MATERIALIZED|COPY\b|CREATE\s+TRIGGER|CREATE\s+VIEW)\b/i.test(sql);
  return { touches, uncertain };
}
function matches(source, touch) {
  const ruleName = fullName(source.name);
  if (source.kind === touch.kind) return ruleName === touch.name || (touch.kind === "function" && touch.name.startsWith(ruleName+"("));
  if (source.kind === "column" && touch.kind === "table") return ruleName.startsWith(touch.name + ".");
  if (source.kind === "table" && touch.kind === "column") return touch.name.startsWith(ruleName + ".");
  return false;
}
export function planDependencyImpact(input) {
  const rules = input?.rules;
  validateRules(rules);
  const planTouches = extractPlanTouches(input.plan);
  const sqlResult = input.sql === undefined ? {touches:[],uncertain:false} : extractSqlTouches(input.sql);
  const touches = [...planTouches,...sqlResult.touches];
  const affected = rules.flatMap(rule => {
    const reasons = touches.filter(touch => rule.sources.some(source => matches(source,touch)));
    return reasons.length ? [{id:rule.id,kind:rule.kind,action:rule.kind === "cache" ? "review-cache-compatibility" : "review-security-semantics",
      evidence: reasons}] : [];
  });
  const report = {version:1,affected,uncertain:sqlResult.uncertain,
    requiresReview:affected.length > 0 || sqlResult.uncertain,
    touches};
  return {...report,digest:checksumText(JSON.stringify(report))};
}
export function assertDependencyImpactReviewed(report, review) {
  if (!report?.requiresReview) return;
  if (!review || review.digest !== report.digest ||
      typeof review.reason !== "string" || !review.reason.trim() ||
      !Array.isArray(review.decisions) ||
      report.affected.some(item=>!review.decisions.some(decision=>decision.id===item.id &&
        ["compatible","update-cache","disable-cache","versioned-rollout"].includes(decision.action) &&
        typeof decision.reason==="string" && decision.reason.trim()))) {
    throw new Error("Dependency impact requires an exact-digest review with explicit per-dependency decisions");
  }
}
