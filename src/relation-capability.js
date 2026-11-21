/**
 * Extra live-catalog ownership preflight for NEW migrations only.
 * Not an SQL interpreter: PG17 upgrade replay remains mandatory, especially
 * for dynamic DO blocks, changing ownership, DDL dependencies and search_path.
 */
import { structuralSql } from "./owner-maintenance.js";
// Accept canonical lower-case identifiers, quoted or unquoted.
const ident = '(?:"([a-z_][a-z0-9_$]*)"|([a-z_][a-z0-9_$]*))';
const qualified = new RegExp('^' + ident + '\\.' + ident + '$');
function normalizeQualified(name) {
  const match = qualified.exec(name);
  if (!match) return null;
  return (match[1] ?? match[2]) + '.' + (match[3] ?? match[4]);
}
const TOKEN = "([^\\s,;(]+)";
function rule(label, head, pattern) {
  return {label,head:new RegExp(head,"ig"),pattern:new RegExp(pattern,"ig")};
}
const OWNED = [
 rule("ALTER TABLE","\\balter\\s+table\\b","\\balter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?"+TOKEN),
 rule("DROP TABLE","\\bdrop\\s+table\\b","\\bdrop\\s+table\\s+(?:if\\s+exists\\s+)?"+TOKEN),
 rule("TRIGGER","\\b(?:create\\s+(?:or\\s+replace\\s+)?(?:constraint\\s+)?|alter\\s+|drop\\s+)trigger\\b","\\b(?:create\\s+(?:or\\s+replace\\s+)?(?:constraint\\s+)?|alter\\s+|drop\\s+)trigger\\s+[^;]*?\\bon\\s+"+TOKEN),
 rule("POLICY","\\b(?:create|alter|drop)\\s+policy\\b","\\b(?:create|alter|drop)\\s+policy\\s+[^;]*?\\bon\\s+"+TOKEN),
 rule("CREATE INDEX","\\bcreate\\s+(?:unique\\s+)?index\\b","\\bcreate\\s+(?:unique\\s+)?index(?:\\s+concurrently)?(?:\\s+if\\s+not\\s+exists)?\\s+[^;]*?\\bon\\s+(?:only\\s+)?"+TOKEN),
 rule("INDEX","\\b(?:alter|drop)\\s+index\\b","\\b(?:alter|drop)\\s+index\\s+(?:if\\s+exists\\s+)?"+TOKEN),
 rule("VIEW","\\b(?:alter|drop)\\s+(?:materialized\\s+)?view\\b","\\b(?:alter|drop)\\s+(?:materialized\\s+)?view\\s+(?:if\\s+exists\\s+)?"+TOKEN),
 rule("REPLACE VIEW","\\bcreate\\s+or\\s+replace\\s+view\\b","\\bcreate\\s+or\\s+replace\\s+view\\s+"+TOKEN),
];
const NEW = [
 rule("CREATE TABLE","\\bcreate\\s+(?:(?:unlogged|temp|temporary)\\s+)?table\\b","\\bcreate\\s+(?:(?:unlogged|temp|temporary)\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?"+TOKEN),
 rule("CREATE VIEW","\\bcreate\\s+(?:or\\s+replace\\s+)?view\\b","\\bcreate\\s+(?:or\\s+replace\\s+)?view\\s+"+TOKEN),
 rule("CREATE SEQUENCE","\\bcreate\\s+(?:unlogged\\s+)?sequence\\b","\\bcreate\\s+(?:unlogged\\s+)?sequence\\s+(?:if\\s+not\\s+exists\\s+)?"+TOKEN),
];
function targets(body,rule) {
  const all=[...body.matchAll(rule.head)],found=[...body.matchAll(rule.pattern)];
  if(all.length!==found.length) throw Error("migration capability denied: unsupported "+rule.label+" SQL; require explicit qualified form");
  return found.map(match=>{
    const name=match[1];
    const normalized=normalizeQualified(name);
    if(!normalized)
      throw Error("migration capability denied: "+rule.label+" requires lowercase schema-qualified object: "+String(name));
    return {name:normalized,position:match.index,kind:rule.label};
  });
}
function activeRole(body,offset) {
  const changes=[...body.matchAll(/\b(?:set\s+(?:local\s+)?role\s+([a-z_][a-z0-9_$]*)|reset\s+role)\s*;/ig)];
  return changes.filter(change=>change.index<offset).at(-1)?.[1]?.toLowerCase()??null;
}
export async function preflightRelationCapabilities(client,sql) {
  const body=structuralSql(sql,{preserveQuotedIdentifiers:true});
  const writes=OWNED.flatMap(r=>targets(body,r)),created=NEW.flatMap(r=>targets(body,r));
  let login=null;
  for(const item of created) {
    const role=activeRole(body,item.position);
    if(role) {
      const ok=await client.query("SELECT pg_catalog.pg_has_role(current_user,$1,'SET') AS can_set",[role]);
      if(!ok.rows[0]?.can_set)throw Error("migration capability denied: cannot SET ROLE "+role);
    }
    if(!role) {
      if(!login)login=(await client.query("SELECT current_user AS role")).rows[0]?.role;
      if(!login)throw Error("migration capability denied: unknown login role");
    }
    const schema=item.name.split(".")[0];
    const grant=await client.query("SELECT has_schema_privilege($1,$2,'CREATE') AS can_create",[role??login,schema]);
    if(!grant.rows[0]?.can_create)
      throw Error("migration capability denied: no CREATE on schema "+schema+" for "+item.kind);
  }
  for(const item of writes) {
    if(item.kind==="DROP TABLE" && /,\s*[a-z_]/i.test(body.slice(item.position,body.indexOf(";",item.position)<0?body.length:body.indexOf(";",item.position))))
      throw Error("migration capability denied: multi-object DROP TABLE needs explicit review");
    const result=await client.query(
      "SELECT o.rolname AS owner, pg_catalog.pg_has_role(current_user,o.oid,'USAGE') AS can_alter, "+
      "pg_catalog.pg_has_role(current_user,o.oid,'SET') AS can_set "+
      "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles o ON o.oid=c.relowner "+
      "WHERE c.oid=pg_catalog.to_regclass($1)",[item.name]);
    if(!result.rows.length) {
      if(created.some(c=>c.name===item.name&&c.position<=item.position))continue;
      const statement=body.slice(item.position,body.indexOf(";",item.position)<0?body.length:body.indexOf(";",item.position));
      if(/\bif\s+exists\b/i.test(statement)&&item.kind.startsWith("DROP"))continue;
      throw Error("migration capability denied: "+item.kind+" object not found: "+item.name);
    }
    const owner=result.rows[0],role=activeRole(body,item.position);
    if(owner.can_alter||(role===owner.owner&&owner.can_set))continue;
    throw Error("migration capability denied: cannot "+item.kind+" "+item.name+"; owner is "+owner.owner);
  }
  return {checked:writes.length,created:created.length};
}
