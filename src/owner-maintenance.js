/**
 * Shared PostgreSQL owner maintenance policy, intentionally opt-in.
 * A recipe allows only reviewed function DDL; it never authorizes itself.
 */
const ID = /^[a-z_][a-z0-9_]*$/;
const FUNCTION_DDL = /\b(?:create\s+(?:or\s+replace\s+)?|alter\s+|drop\s+)function\s+((?:[a-z_][a-z0-9_]*\.)?[a-z_][a-z0-9_]*)\s*\(/ig;
const strip = sql => sql.replace(/--[^\r\n]*/g,"").replace(/\/\*[\s\S]*?\*\//g,"");
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
    const functions=[...body.matchAll(FUNCTION_DDL)].map(m=>m[1].toLowerCase());
    if(!functions.length || functions.some(fn=>fn!==target) || /\bdrop\s+function\b/i.test(body))
      throw Error("owner policy unexpected function DDL: "+target);
    const role=esc(rule.role),schema=esc(rule.schema),fn=esc(target);
    if(new RegExp("\\b(?:grant\\s+"+role+"\\s+to|alter\\s+role\\s+"+role+")\\b","i").test(body))
      throw Error("owner policy forbids SQL role grants");
    const grant=new RegExp("\\bgrant\\s+create\\s+on\\s+schema\\s+"+schema+"\\s+to\\s+"+role+"\\s*;","i");
    const revoke=new RegExp("\\brevoke\\s+create\\s+on\\s+schema\\s+"+schema+"\\s+from\\s+"+role+"\\s*;","i");
    if(!grant.test(body)||!revoke.test(body)||body.search(grant)>body.search(revoke))
      throw Error("owner policy requires temporary CREATE grant and revoke");
    if(rule.mode==="set-role") {
      if(!new RegExp("\\bset\\s+local\\s+role\\s+"+role+"\\s*;","i").test(body)||!/\breset\s+role\s*;/i.test(body))
        throw Error("owner policy requires SET LOCAL ROLE and RESET ROLE");
    } else if(!new RegExp("\\balter\\s+function\\s+"+fn+"\\s*\\([^;]*\\)\\s+owner\\s+to\\s+"+role+"\\s*;","i").test(body))
      throw Error("owner policy requires restricted function owner transfer");
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
  if(!state||state.role!==state.login||state.rolsuper||state.rolbypassrls||state.inherited)
    throw Error("owner maintenance requires non-superuser and non-inheriting migration login");
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
