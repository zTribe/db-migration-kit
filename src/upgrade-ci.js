import { execFileSync } from "node:child_process";
import { loadManifest } from "./checksum.js";

/** Derive an upgrade prefix from Git, independently of the proposed target state. */
export async function resolveUpgradePrefix(config, base, repository) {
  if (!/^[a-f0-9]{40}$/i.test(base)) throw new Error("Expected an upgrade base commit SHA");
  const git = (...args) => execFileSync("git", args, { cwd: repository, encoding: "utf8" });
  const prefix = new Set(git("ls-tree", "-r", "--name-only", base, "--", "db/migrations/")
    .split("\n").filter(file => /\/(?:\d{3}|\d{14})_[a-z0-9_]+\.sql$/.test(file)).map(file => file.slice("db/migrations/".length)));
  const manifest = await loadManifest(config);
  const existing = manifest.filter(entry => prefix.has(entry.file));
  if (!existing.length || existing.length !== prefix.size ||
      existing.some((entry, index) => entry !== manifest[index])) {
    throw new Error("Base migrations must be a contiguous prefix of the proposed manifest");
  }
  for (const entry of existing) {
    if (git("show", `${base}:db/migrations/${entry.file}`) !== entry.sql) {
      throw new Error(`Base migration changed: ${entry.file}`);
    }
  }
  return { existing, pending: manifest.slice(existing.length) };
}

/** Reproduce the PostgreSQL attributes of selected application roles in a disposable database. */
export async function restoreUpgradeRoles(client, base, repository, names) {
  const { permissions } = JSON.parse(execFileSync("git",
    ["show", `${base}:db/migration-target.json`], { cwd: repository, encoding: "utf8" }));
  for (const name of names) {
    const role = permissions.roles.find(row => row.rolname === name);
    if (!role || !/^[a-z_][a-z0-9_]*$/.test(name) || role.rolsuper || role.rolreplication ||
        role.rolcreatedb || role.rolcreaterole) throw new Error(`Unsupported upgrade fixture role: ${name}`);
    if (permissions.memberships.some(row => row.member === name)) {
      throw new Error(`Upgrade fixture must explicitly model memberships for ${name}`);
    }
    const { rows: [existing] } = await client.query("SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1) AS present", [name]);
    await client.query(`${existing.present ? "ALTER" : "CREATE"} ROLE "${name}"
      ${role.rolcanlogin ? "LOGIN" : "NOLOGIN"} ${role.rolinherit ? "INHERIT" : "NOINHERIT"}
      ${role.rolbypassrls ? "BYPASSRLS" : "NOBYPASSRLS"} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION`);
  }
}
