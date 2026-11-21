#!/usr/bin/env node
import { readFile, writeFile, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { readTargetState, checksumText, createMigration, loadMigrationConfig, planMigration, assertMigrationReview, generateMigrationSql, applyMigrations, auditMigrations, inspectMigrations, inspectRuntimeSecurity, verifyDatabaseTarget, planDependencyImpact, planDependencyImpactAst, assertDependencyImpactReviewed } from "../src/index.js";

const [command = "status", ...args] = process.argv.slice(2);
if (command === "draft-check") {
  const { dirname, relative, isAbsolute } = await import("node:path");
  const { checkAiMigrationDraft } = await import("../src/ai-draft-check.js");
  const configPath = resolve(process.cwd(), args.find(x => x.startsWith("--config="))?.slice(9) ?? "db/migration-kit.config.json");
  const source = args.find(x => x.startsWith("--sql="))?.slice(6);
  const name = args.find(x => x.startsWith("--name="))?.slice(7);
  if (!source || !name) throw Error("Usage: db-migrate-kit draft-check --config=db/migration-kit.config.json --sql=candidate.sql --name=snake_case");
  const config = await loadMigrationConfig(configPath);
  const candidate = resolve(source);
  const rel = relative(config.directory,candidate);
  if (!rel.startsWith("..") && !isAbsolute(rel))
    throw Error("Candidate must be outside db/migrations; historical SQL is immutable");
  const ownerConfig = JSON.parse(await readFile(resolve(dirname(configPath),"owner-maintenance-policy.json"),"utf8"));
  const report = await checkAiMigrationDraft({name,sql:await readFile(candidate,"utf8"),ownerConfig});
  console.log(JSON.stringify(report,null,2));
  if (!report.ok) process.exitCode=1;
  process.exit();
}
if (command === "prepare") {
  await import("./test-local.js");
  process.exit(0);
}
const configPath = resolve(process.cwd(), args.find(arg => arg.startsWith("--config="))?.slice(9) ?? "migration-kit.config.json");
const config = await loadMigrationConfig(configPath);
const readJson = async path => JSON.parse(await readFile(path, "utf8"));

if (command === "scan-history") {
  const { scanMigrationHistoryAst } = await import("../src/migration-history-ast.js");
  const changedPath = args.find(arg => arg.startsWith("--changed-files="))?.slice(16);
  const changedFiles = changedPath
    ? (await readFile(resolve(process.cwd(),changedPath),"utf8")).split(/\r?\n/).map(x=>x.trim()).filter(Boolean)
    : [];
  const report = await scanMigrationHistoryAst(config,{changedFiles});
  const output = args.find(arg => arg.startsWith("--out="))?.slice(6);
  if (output) await writeFile(resolve(process.cwd(),output),JSON.stringify(report,null,2)+"\n");
  console.log(JSON.stringify({summary:report.summary,releaseApproved:false,
    report:output ?? null,warnings:report.warnings},null,2));
  // Parse errors on changed migrations require review and authoritative PG17
  // replay. Do not block valid PG17 SQL because a PG18 parser disagrees.
  if (args.includes("--fail-on-parse-error") && report.summary.parseErrors > 0) process.exitCode=1;
  process.exit();
}

if (command === "impact") {
  const rulesPath = args.find(arg => arg.startsWith("--rules="))?.slice(8);
  const sqlPath = args.find(arg => arg.startsWith("--sql="))?.slice(6);
  const fromPath = args.find(arg => arg.startsWith("--from="))?.slice(7);
  const toPath = args.find(arg => arg.startsWith("--to="))?.slice(5);
  if (!rulesPath || (!sqlPath && !(fromPath && toPath))) {
    throw new Error("impact requires --rules=<project-dependencies.json> and --sql=<migration.sql> or --from/--to states");
  }
  const manifest = await readJson(resolve(process.cwd(), rulesPath));
  const rules = Array.isArray(manifest) ? manifest : manifest.rules;
  const plan = fromPath && toPath
    ? planMigration(await readJson(resolve(process.cwd(),fromPath)), await readJson(resolve(process.cwd(),toPath)))
    : undefined;
  const sql = sqlPath ? await readFile(resolve(process.cwd(),sqlPath),"utf8") : undefined;
  const report = args.includes("--ast")
    ? await planDependencyImpactAst({rules,plan,sql})
    : planDependencyImpact({rules,plan,sql});
  const outputPath = args.find(arg => arg.startsWith("--out="))?.slice(6);
  if (outputPath) await writeFile(resolve(process.cwd(),outputPath),JSON.stringify(report,null,2)+"\n");
  console.log(JSON.stringify(report,null,2));
  const checkPath = args.find(arg => arg.startsWith("--check="))?.slice(8);
  if (checkPath) {
    const review = await readJson(resolve(process.cwd(),checkPath));
    assertDependencyImpactReviewed(report,review);
  } else if (args.includes("--require-reviewed") && report.requiresReview) {
    throw new Error("Migration dependency changes require --check=<review.json>");
  }
  process.exit(0);
}

if (["validate", "plan", "review", "generate"].includes(command)) {
  if (command !== "validate") {
    const from = args.find(arg => arg.startsWith("--from="))?.slice(7);
    const to = args.find(arg => arg.startsWith("--to="))?.slice(5) ?? config.targetState;
    if (!from || !to) throw new Error("Specify --from=path and --to=path, or configure targetState");
    const before = await readJson(from);
    const after = await readJson(to);
    const plan = planMigration(before, after);
    if (command === "plan") console.log(JSON.stringify(plan, null, 2));
    else {
      const reviewPath = args.find(arg => arg.startsWith("--review="))?.slice(9) ?? config.review;
      const review = reviewPath ? await readJson(reviewPath) : undefined;
      if (command === "review") assertMigrationReview(plan, review);
      else {
        const sql = generateMigrationSql(before, after, review);
        const name = args.find(arg => arg.startsWith("--name="))?.slice(7);
        if (!name) console.log(sql);
        else {
          const file = await createMigration(config, name, sql);
          try {
            if (config.requireMigrationGuards) {
              await writeFile(file + ".review.json", JSON.stringify({
                before, after, review, sqlChecksum: checksumText(sql.trimEnd() + "\n"),
              }, null, 2) + "\n", { flag: "wx" });
            }
          } catch (error) {
            await unlink(file);
            throw error;
          }
          console.log(file);
        }
      }
    }
  }
  process.exit(0);
}

const { default: pg } = await import("pg");
const databaseUrl = process.env.MIGRATION_DATABASE_URL ?? process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("Set MIGRATION_DATABASE_URL (preferred) or DATABASE_URL.");
const parsed = new URL(databaseUrl);
if (!["postgres:","postgresql:"].includes(parsed.protocol)) throw new Error("Database URL must use postgres:// or postgresql://.");
const local = ["localhost","127.0.0.1","::1","[::1]"].includes(parsed.hostname);
if (!local && command === "apply" && !args.includes("--allow-remote")) throw new Error("Remote database apply blocked; --allow-remote must be explicit.");
if (!local && command === "apply" && (!config.targetIdentity || config.targetIdentity.environment !== "dev")) throw new Error("Remote apply requires independently provisioned targetIdentity for the Dev database.");
if (parsed.search) throw new Error("Database URL query parameters are unsupported; configure TLS explicitly to prevent SSL override.");
if (command === "apply" && !args.includes("--yes")) throw new Error("Apply requires explicit --yes confirmation.");
const pool = new pg.Pool({
  host: parsed.hostname,
  port: Number(parsed.port || "5432"),
  user: decodeURIComponent(parsed.username),
  password: decodeURIComponent(parsed.password),
  database: decodeURIComponent(parsed.pathname.slice(1) || "postgres"),
  max: 1,
  connectionTimeoutMillis: 10000,
  application_name: "db-migration-kit-cli",
  ssl: local ? undefined : { rejectUnauthorized: true },
});
try {
  const options = {
    ...config,
    directory: resolve(process.cwd(), config.directory),
    ...(!local && command === "apply" ? { verifyTarget: client => verifyDatabaseTarget(client, config.targetIdentity) } : {}),
  };
  if (command === "snapshot") {
    const schemas = args.find(arg => arg.startsWith("--schemas="))?.slice(10).split(",") ?? [config.schema ?? "public"];
    if (schemas.some(schema => !schema.trim())) throw new Error("Specify nonempty schema names");
    const client = await pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      const state = await readTargetState(client, schemas);
      if (state.permissions.schemas.length !== new Set(schemas).size) throw new Error("Snapshot schema does not exist");
      console.log(JSON.stringify(state, null, 2));
    } finally {
      try { await client.query("ROLLBACK"); }
      finally { client.release(); }
    }
  } else if (command === "status") {
    const report = await inspectMigrations(pool, options);
    console.log(JSON.stringify({ ok: report.ok, applied: report.applied.length, pending: report.pending.map(x=>x.version), unknown: report.unknown, drift: report.drift }, null, 2));
    if (!report.ok) process.exitCode = 1;
  } else if (command === "audit") {
    const report = await auditMigrations(pool, options);
    console.log(`PASS: ${report.applied.length} applied migrations; no checksum drift.`);
  } else if (command === "apply") {
    const report = await applyMigrations(pool, options);
    console.log(`Applied ${report.applied.length} migration(s).`);
  } else if (command === "security") {
    if (!config.security) throw new Error("Add a security section to migration-kit.config.json.");
    const report = await inspectRuntimeSecurity(pool, config.security);
    console.log(JSON.stringify(report, null, 2));
    if (!report.ok) process.exitCode = 1;
  } else {
    throw new Error("Usage: db-migrate-kit <status|audit|apply|security|snapshot> [--config=path] [--yes] [--allow-remote]");
  }
} finally {
  await pool.end();
}
