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

/** Report each database/default ACL mismatch against the Git base snapshot. */
export async function compareUpgradeAcl(client, base, repository) {
  if (!/^[a-f0-9]{40}$/i.test(base)) throw new Error("Expected an upgrade base commit SHA");
  const expected = JSON.parse(execFileSync("git",
    ["show", `${base}:db/migration-permissions-extra.json`], { cwd: repository, encoding: "utf8" }));
  const { rows: [database] } = await client.query(`
    SELECT pg_catalog.pg_get_userbyid(datdba) AS owner,
           coalesce(datacl, pg_catalog.acldefault('d', datdba))::text[] AS acl
    FROM pg_catalog.pg_database WHERE datname = current_database()
  `);
  const { rows: defaults } = await client.query(`
    SELECT pg_catalog.pg_get_userbyid(d.defaclrole) AS owner, n.nspname AS schema,
           d.defaclobjtype AS object_type, d.defaclacl::text[] AS acl
    FROM pg_catalog.pg_default_acl d
    LEFT JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace
  `);
  const normalize = async acl => (await client.query(
    "SELECT ARRAY(SELECT unnest($1::text[]) ORDER BY 1) AS acl", [acl],
  )).rows[0].acl;
  const diffs = [];
  if (database.owner !== expected.database.owner ||
      JSON.stringify([...database.acl].sort()) !== JSON.stringify([...(await normalize(expected.database.effective_acl))].sort())) {
    diffs.push("database owner or ACL");
  }
  const key = row => JSON.stringify([row.owner, row.schema, row.object_type]);
  const byKey = new Map(defaults.map(row => [key(row), row.acl]));
  for (const row of expected.defaultPrivileges) {
    const id = key(row);
    const actual = byKey.get(id);
    if (!actual || JSON.stringify([...actual].sort()) !== JSON.stringify([...(await normalize(row.acl))].sort())) {
      diffs.push(`default ACL ${id}`);
    }
    byKey.delete(id);
  }
  for (const id of byKey.keys()) diffs.push(`unexpected default ACL ${id}`);
  return diffs;
}
