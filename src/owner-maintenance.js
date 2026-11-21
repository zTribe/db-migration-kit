/**
 * Shared PostgreSQL owner maintenance policy, intentionally opt-in.
 * A recipe allows only reviewed function DDL; it never authorizes itself.
 */
const ID = /^[a-z_][a-z0-9_]*$/;
const FUNCTION_DDL = /\b(?:create\s+(?:or\s+replace\s+)?|alter\s+|drop\s+)function\s+((?:[a-z_][a-z0-9_]*\.)?[a-z_][a-z0-9_]*)\s*\(/ig;
/**
 * Preserve SQL offsets while hiding quoted strings, dollar-quoted PL/pgSQL
 * bodies and comments. Owner authorization must never be matched inside data.
 */
function structuralSql(sql) {
  const out = sql.split("");
  const mask = (a, b) => {
    for (let k = a; k < b; k++) if (!/\s/.test(out[k])) out[k] = " ";
  };
  let i = 0;
  while (i < sql.length) {
    const start = i;
    if (sql.startsWith("--", i)) {
      i = sql.indexOf("\n", i);
      if (i === -1) i = sql.length;
      mask(start, i);
      continue;
    }
    if (sql.startsWith("/*", i)) {
      i += 2;
      let depth = 1;
      while (depth && i < sql.length) {
        if (sql.startsWith("/*", i)) { depth++; i += 2; }
        else if (sql.startsWith("*/", i)) { depth--; i += 2; }
        else i++;
      }
      if (depth) throw Error("unclosed SQL block comment in owner policy");
      mask(start, i);
      continue;
    }
    if (sql[i] === "'" || sql[i] === '"') {
      const quote = sql[i];
      const escapeString = quote === "'" && /[eE]/.test(sql[i - 1] ?? "") &&
        (i < 2 || !/[a-z0-9_$]/i.test(sql[i - 2]));
      i++;
      let closed = false;
      while (i < sql.length) {
        if (escapeString && sql[i] === "\\") { i += 2; continue; }
        if (sql[i] === quote) {
          if (sql[i + 1] === quote) { i += 2; continue; }
          i++;
          closed = true;
          break;
        }
        i++;
      }
      if (!closed) throw Error("unclosed SQL quoted literal in owner policy");
      mask(start, i);
      continue;
    }
    if (sql[i] === "$") {
      const tagged = /^(?:\$\$|\$[a-z_][a-z_0-9]*\$)/i.exec(sql.slice(i));
      if (tagged) {
        const tag = tagged[0];
        const end = sql.indexOf(tag, i + tag.length);
        if (end < 0) throw Error("unclosed SQL dollar body in owner policy");
        i = end + tag.length;
        mask(start, i);
        continue;
      }
    }
    i++;
  }
  return out.join("");
}
const strip = structuralSql;
const ident = s => { if(typeof s!=="string" || !ID.test(s)) throw Error("invalid owner policy identifier"); return s; };
const qi = s => '"' + ident(s) + '"';
const esc = s => s.replace(/[.*+?^$()|[\]{}]/g,"\\$&");
const SENSITIVE = /\b(?:set\s+(?:local\s+)?role|grant\s+create\s+on\s+schema|owner\s+to\s+[a-z_][a-z0-9_]*|grant\s+[a-z_][a-z0-9_]*\s+to\s+current_user)\b/i;

export function createOwnerMaintenancePolicy({recipes=[],legacyThrough=""}={}) {
  if(!Array.isArray(recipes)) throw Error("invalid owner recipes");
  const entries=new Map();
  for(const recipe of recipes) {
    const rule=Object.freeze({
      name:ident(recipe.name),role:ident(recipe.role),schema:ident(recipe.schema),
      functionName:ident(recipe.functionName),mode:recipe.mode,
      version:recipe.version || null
    });
    if(!["set-role","transfer"].includes(rule.mode)||entries.has(rule.name)) throw Error("duplicate/invalid owner recipe");
    if(rule.version&&!/^\d{3,14}_[a-z0-9_]+$/.test(rule.version)) throw Error("invalid owner recipe version");
    entries.set(rule.name,rule);
  }
  function verify(sql,rule) {
    if(typeof sql!=="string"||!sql.trim()) throw Error("owner maintenance requires reviewed SQL");
    const body=strip(sql),target=rule.schema+"."+rule.functionName;
    const functions=[...body.matchAll(FUNCTION_DDL)];
    if(!functions.length||functions.some(m=>m[1].toLowerCase()!==target)||
        /\bdrop\s+function\b/i.test(body))
      throw Error("owner policy unexpected function DDL: "+target);
    // A reviewed Owner recipe must be limited to its approved function,
    // never a convenient escape hatch for unrelated schema/role operations.
    if(/\b(?:create\s+(?:or\s+replace\s+)?|alter\s+|drop\s+)(?:table|view|materialized\s+view|index|trigger|policy|role|schema|extension|sequence)\b/i.test(body))
      throw Error("owner policy forbids unrelated object DDL");
    const role=esc(rule.role),schema=esc(rule.schema),fn=esc(target);
    const grantPattern=new RegExp("\\bgrant\\s+create\\s+on\\s+schema\\s+"+schema+"\\s+to\\s+"+role+"\\s*;","ig");
    const revokePattern=new RegExp("\\brevoke\\s+create\\s+on\\s+schema\\s+"+schema+"\\s+from\\s+"+role+"\\s*;","ig");
    const grants=[...body.matchAll(/\bgrant\b/ig)];
    const revokes=[...body.matchAll(/\brevoke\b/ig)];
    const grant=[...body.matchAll(grantPattern)],revoke=[...body.matchAll(revokePattern)];
    if(grants.length!==1||revokes.length!==1||grant.length!==1||revoke.length!==1||
        grant[0].index>=revoke[0].index)
      throw Error("owner policy requires one ordered temporary CREATE grant and revoke");
    const sets=[...body.matchAll(/\bset\s+(?:local\s+)?role\s+([a-z_][a-z_0-9]*)\s*;/ig)];
    const resets=[...body.matchAll(/\breset\s+role\s*;/ig)];
    const firstFunction=functions[0].index,lastFunction=functions.at(-1).index;
    if(rule.mode==="set-role") {
      if(sets.length!==1||resets.length!==1||
          sets[0][1].toLowerCase()!==rule.role)
        throw Error("owner policy requires exactly one SET LOCAL ROLE and RESET ROLE");
      if(!/\bset\s+local\s+role\b/i.test(sets[0][0])||
          !(grant[0].index<sets[0].index&&sets[0].index<firstFunction&&
            lastFunction<resets[0].index&&resets[0].index<revoke[0].index)||
          /\bowner\s+to\b/i.test(body))
        throw Error("owner policy SET LOCAL ROLE / RESET ROLE must enclose only the reviewed function DDL");
    } else {
      if(sets.length||resets.length) throw Error("owner transfer recipe forbids SET/RESET ROLE");
      const transfers=[...body.matchAll(new RegExp("\\balter\\s+function\\s+"+fn+"\\s*\\([^;]*\\)\\s+owner\\s+to\\s+"+role+"\\s*;","ig"))];
      if(transfers.length!==1||!functions.some(m=>m.index<transfers[0].index&&
          /\bcreate\b/i.test(m[0]))||
          !(grant[0].index<firstFunction&&transfers[0].index<revoke[0].index))
        throw Error("owner policy requires restricted function owner transfer before CREATE revoke");
    }
    return rule;
  }

  function forMigration(migration) {
    const v=migration?.version||"";
    const rule=[...entries.values()].find(r=>r.version===v||
      (!r.version&&new RegExp("^\\d{3,14}_"+esc(r.name)+"$").test(v)));
    if(rule) return verify(migration.sql,rule);
    if((!legacyThrough || v>legacyThrough)&&SENSITIVE.test(strip(migration?.sql||"")))
      throw Error("owner-sensitive migration requires approved recipe: "+v);
    return null;
  }
  function forCandidate(name,sql) {
    const rule=entries.get(name);
    if(rule) return verify(sql,rule);
    if(SENSITIVE.test(strip(sql||""))) throw Error("owner-sensitive candidate requires approved recipe: "+name);
    return null;
  }
  return Object.freeze({forMigration,forCandidate});
}

/**
 * Transactional capability helper for trusted migration runners only.
 * Requires independent ADMIN OPTION; never grants inherited membership.
 * Caller uses these within the same Kit-managed migration transaction.
 */
export async function acquireTemporaryOwnerRole(client,{role,schema}) {
  role=ident(role);schema=ident(schema);
  const {rows:[state]}=await client.query(
    "SELECT current_user AS role, session_user AS login, r.rolsuper, r.rolbypassrls, "+
    "pg_has_role(current_user,$1,'USAGE') AS inherited, "+
    "pg_has_role(current_user,$1,'SET') AS can_set, "+
    "EXISTS(SELECT FROM pg_auth_members m WHERE m.roleid=$1::regrole AND m.member=current_user::regrole AND m.admin_option) AS admin_option, "+
    "EXISTS(SELECT FROM pg_auth_members m WHERE m.roleid=$1::regrole AND m.member=current_user::regrole AND m.grantor=current_user::regrole) AS self_grant "+
    "FROM pg_roles r WHERE r.rolname=current_user",[role]);
  if(!state||state.role!==state.login||state.rolsuper||state.inherited)
    throw Error("owner maintenance requires non-superuser migration login without inherited runtime owner");
  if(state.can_set) return Object.freeze({role,schema,added:false});
  if(!state.admin_option||state.self_grant) throw Error("owner maintenance missing external ADMIN OPTION");
  await client.query("GRANT "+qi(role)+" TO "+qi(state.role)+" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE GRANTED BY "+qi(state.role));
  const {rows:[check]}=await client.query(
    "SELECT pg_has_role(current_user,$1,'SET') AS can_set, pg_has_role(current_user,$1,'USAGE') AS inherited",[role]);
  if(!check?.can_set||check.inherited) throw Error("owner temporary SET capability not confirmed");
  return Object.freeze({role,schema,added:true});
}
export async function releaseTemporaryOwnerRole(client,lease) {
  if(!lease||typeof lease.added!=="boolean") throw Error("invalid owner capability lease");
  if(lease.added) {
    const {rows:[r]}=await client.query("SELECT current_user AS login");
    await client.query("REVOKE "+qi(lease.role)+" FROM "+qi(r.login)+" GRANTED BY "+qi(r.login));
  }
  const {rows:[check]}=await client.query(
    "SELECT pg_has_role(current_user,$1,'SET') AS can_set, "+
    "pg_has_role(current_user,$1,'USAGE') AS inherited, "+
    "has_schema_privilege($1,$2,'CREATE') AS schema_create",[lease.role,lease.schema]);
  if(!check||check.inherited||check.schema_create||(lease.added&&check.can_set))
    throw Error("owner maintenance privileges not restored");
}
