#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { applyMigrations, auditMigrations, inspectMigrations, inspectRuntimeSecurity, verifyDatabaseTarget } from "../src/index.js";

const [command = "status", ...args] = process.argv.slice(2);
const configPath = resolve(process.cwd(), args.find(arg => arg.startsWith("--config="))?.slice(9) ?? "migration-kit.config.json");
let config;
try { config = JSON.parse(await readFile(configPath, "utf8")); }
catch (error) { throw new Error(`Cannot read ${configPath}. Copy migration-kit.config.example.json and edit it.`, { cause: error }); }
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
  if (command === "status") {
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
    throw new Error("Usage: db-migrate-kit <status|audit|apply|security> [--config=path] [--yes] [--allow-remote]");
  }
} finally {
  await pool.end();
}
