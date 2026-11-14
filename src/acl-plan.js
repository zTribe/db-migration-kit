// Handle simple PostgreSQL aclitem arrays. Quoted roles and grant chains
// require explicit migration SQL and verification under the intended grantor.
const privileges = {
  r: { a: "INSERT", r: "SELECT", w: "UPDATE", d: "DELETE", D: "TRUNCATE", x: "REFERENCES", t: "TRIGGER", m: "MAINTAIN" },
  S: { r: "SELECT", w: "UPDATE", U: "USAGE" },
  schema: { U: "USAGE", C: "CREATE" },
};

function parse(acl, owner, supported) {
  if (typeof acl !== "string" || !/^\{[^{}]*\}$/.test(acl)) return null;
  const entries = new Map();
  for (const item of acl.slice(1, -1).split(",").filter(Boolean)) {
    const match = /^([a-zA-Z0-9_]*)=([a-zA-Z]*)\/([a-zA-Z0-9_]+)$/.exec(item);
    if (!match || match[3] !== owner) return null;
    for (const letter of match[2]) {
      if (!Object.hasOwn(supported, letter)) return null;
      entries.set(JSON.stringify([match[1], letter]), [match[1], supported[letter]]);
    }
  }
  return entries;
}

export function renderAcl({ section, identity, previous, desired }, quote) {
  if (!previous || !desired || !["schemas", "objects"].includes(section)) return null;
  const { acl: oldAcl, ...oldState } = previous;
  const { acl: newAcl, ...newState } = desired;
  if (JSON.stringify(oldState) !== JSON.stringify(newState)) return null;
  const kind = section === "schemas" ? "schema" : previous.kind;
  const supported = privileges[["p", "v", "m", "f"].includes(kind) ? "r" : kind];
  if (!supported) return null;
  const from = parse(oldAcl, previous.owner, supported);
  const to = parse(newAcl, previous.owner, supported);
  if (!from || !to) return null;
  const object = kind === "schema" ? "SCHEMA" : kind === "S" ? "SEQUENCE" : "TABLE";
  const target = `${object} ${identity.map(quote).join(".")}`;
  const statements = [];
  for (const [source, other, action, direction] of [[from, to, "REVOKE", "FROM"], [to, from, "GRANT", "TO"]]) {
    for (const key of [...source.keys()].sort()) {
      if (other.has(key)) continue;
      const [role, privilege] = source.get(key);
      if (role === previous.owner) return null;
      statements.push(`${action} ${privilege} ON ${target} ${direction} ${role ? quote(role) : "PUBLIC"};`);
    }
  }
  return statements.length ? statements.join("\n") : null;
}
