import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

export function checksumText(sql) {
  return createHash("sha256").update(sql, "utf8").digest("hex");
}

export async function loadManifest({ directory, files }) {
  if (!Array.isArray(files) || files.length === 0) {
    throw new Error("migration files must be a non-empty ordered array");
  }
  const seen = new Set();
  const migrations = [];
  for (const entry of files) {
    const file = typeof entry === "string" ? entry : entry.file;
    const version = typeof entry === "string" ? basename(entry).replace(/\.sql$/i, "") : entry.version;
    if (!file || !version || file.includes("..") || file.startsWith("/") || !file.endsWith(".sql")) {
      throw new Error(`invalid migration entry: ${JSON.stringify(entry)}`);
    }
    if (seen.has(version)) throw new Error(`duplicate migration version: ${version}`);
    seen.add(version);
    const sql = await readFile(resolve(directory, file), "utf8");
    if (!sql.trim()) throw new Error(`migration is empty: ${file}`);
    migrations.push({ version, name: basename(file), file, sql, checksum: checksumText(sql) });
  }
  return migrations;
}
