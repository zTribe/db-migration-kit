import { writeFile } from "node:fs/promises";
import { join } from "node:path";

export async function createMigration(config, name, sql, now = new Date()) {
  if (!/^[a-z][a-z0-9_]*$/.test(name) || !sql.trim()) throw new Error("Migration name and SQL required");
  const latest = config.files.at(-1);
  let prefix;
  if (config.discovery === "counter") {
    const next = Number(latest.slice(0, 3)) + 1;
    if (next > 999) throw new Error("Migration counter exhausted");
    prefix = String(next).padStart(3, "0");
  } else if (config.discovery === "timestamp") {
    prefix = now.toISOString().slice(0, 19).replace(/\D/g, "");
    if (prefix <= latest.slice(0, 14)) throw new Error("Migration timestamp must follow the current manifest");
  } else {
    throw new Error("Migration creation requires discovery");
  }
  const file = join(config.directory, `${prefix}_${name}.sql`);
  await writeFile(file, sql.trimEnd() + "\n", { flag: "wx" });
  return file;
}
