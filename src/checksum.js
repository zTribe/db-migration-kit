import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";

export function checksumText(sql) {
  return createHash("sha256").update(sql, "utf8").digest("hex");
}

export async function loadManifest({ directory, files }) {
  if (typeof directory !== "string" || !directory.trim()) throw new Error("migration directory is required");
  if (!Array.isArray(files) || files.length === 0) throw new Error("migration files must be a non-empty ordered array");
  const root = await realpath(resolve(directory));
  const seenVersions = new Set();
  const seenFiles = new Set();
  const migrations = [];
  let previousVersion = null;
  for (const entry of files) {
    const file = typeof entry === "string" ? entry : entry?.file;
    const version = typeof entry === "string" ? basename(entry).replace(/\.sql$/i, "") : entry?.version;
    if (typeof file !== "string" || !file || file.includes("\\") || isAbsolute(file) ||
        file.split("/").some(part => !part || part === "." || part === "..") || !file.endsWith(".sql") ||
        typeof version !== "string" || !/^[a-z0-9][a-z0-9_-]*$/i.test(version)) {
      throw new Error("invalid migration manifest entry");
    }
    if (seenVersions.has(version)) throw new Error(`duplicate migration version: ${version}`);
    if (seenFiles.has(file)) throw new Error(`duplicate migration file: ${file}`);
    if (previousVersion !== null && version <= previousVersion) throw new Error(`migration manifest is not strictly ordered: ${version}`);
    const target = await realpath(resolve(root, file));
    const rel = relative(root, target);
    if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      throw new Error(`migration path escapes directory: ${file}`);
    }
    const sql = await readFile(target, "utf8");
    if (!sql.trim()) throw new Error(`migration is empty: ${file}`);
    seenVersions.add(version);
    seenFiles.add(file);
    previousVersion = version;
    migrations.push({ version, name: basename(file), file, sql, checksum: checksumText(sql) });
  }
  return migrations;
}
