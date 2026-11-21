import { structuralSql } from "./owner-maintenance.js";
const FUNCTION_DDL = /\b(create(?:\s+or\s+replace)?|drop|alter)\s+function\s+((?:[a-z_][a-z0-9_$]*\.)?[a-z_][a-z0-9_$]*)\s*\(/ig;

/**
 * Historical migrations retain legacy preflight behavior. New migrations can
 * opt into conservative checks; unknown SQL still needs real PG17 replay.
 */
export async function preflightMigrationCapabilities(client, sql, {future=false}={}) {
  const source=future?structuralSql(sql):sql;
  const transitions=[...source.matchAll(/\b(?:set\s+(?:local\s+)?role\s+([a-z_][a-z0-9_$]*)|reset\s+role)\s*;/ig)]
    .map(m=>({position:m.index,role:m[1]?.toLowerCase()??null}));
  const targets=[];
  for(const match of source.matchAll(FUNCTION_DDL)) {
    const verb=match[1].toLowerCase().replace(/\s+/g," ");
    if(!future && verb==="create") continue;
    const qualified=match[2].split(".");
    if(future && qualified.length!==2)
      throw Error("migration capability denied: future function DDL must use qualified schema.function");
    targets.push({schema:qualified.length===2?qualified[0]:"public",name:qualified.at(-1),
      position:match.index,plainCreate:verb==="create"});
  }
  if(!targets.length)return;
  const createGrants=[...source.matchAll(/\bgrant\s+create\s+on\s+schema\s+([a-z_][a-z0-9_$]*)\s+to\s+([a-z_][a-z0-9_$]*)/ig)]
    .map(m=>({key:m[1].toLowerCase()+":"+m[2].toLowerCase(),position:m.index}));
  const plannedCreate=new Set(createGrants.map(x=>x.key));
  // Legacy-only compatibility: future migrations may not pretend that a
  // GRANT to themselves will definitely succeed before running SQL.
  const plannedMembership=future?new Set():new Set([...source.matchAll(
    /\bgrant\s+([a-z_][a-z0-9_$]*)\s+to\s+(?:current_user|%I[^\n]*current_user)/ig
  )].map(m=>m[1].toLowerCase()));
  const identity=await client.query(
    "select current_user as role, coalesce((select rolsuper from pg_catalog.pg_roles where rolname=current_user),false) as superuser"
  );
  const login=identity.rows[0]?.role;
  if(!login)throw Error("migration capability denied: current user is unknown");
  if(identity.rows[0]?.superuser)return;
  for(const target of targets) {
    const activeRole=transitions.filter(x=>x.position<target.position).at(-1)?.role??null;
    const schemaRole=activeRole??login;
    if(future && activeRole) {
      const membership=await client.query("select pg_catalog.pg_has_role(current_user,$1,'SET') as can_set",[activeRole]);
      if(!membership.rows[0]?.can_set)
        throw Error("migration capability denied: current user cannot SET ROLE "+activeRole);
    }
    const privileges=await client.query("select has_schema_privilege($1,$2,'CREATE') as can_create",
      [schemaRole,target.schema]);
    if(!privileges.rows[0]?.can_create) {
      const key=target.schema.toLowerCase()+":"+schemaRole.toLowerCase();
      const grantPresent=future
        ? createGrants.some(x=>x.key===key&&x.position<target.position)
        : plannedCreate.has(key);
      if(!grantPresent)
        throw Error("migration capability denied: "+schemaRole+" lacks CREATE on schema "+
          target.schema+" for function "+target.schema+"."+target.name);
      if(future) {
        const grantable=await client.query(
          "select has_schema_privilege(current_user,$1,'CREATE WITH GRANT OPTION') as can_grant",
          [target.schema]);
        if(!grantable.rows[0]?.can_grant)
          throw Error("migration capability denied: migration login cannot grant CREATE on schema "+target.schema);
      }
    }
    if(target.plainCreate)continue; // New signatures do not require ownership of other overloads.
    const functions=await client.query(
      "select p.oid::regprocedure::text as signature, owner_role.rolname as owner, "+
      "pg_catalog.pg_has_role(current_user,owner_role.oid,'USAGE') as can_alter, "+
      "pg_catalog.pg_has_role(current_user,owner_role.oid,'SET') as can_set "+
      "from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid=p.pronamespace "+
      "join pg_catalog.pg_roles owner_role on owner_role.oid=p.proowner "+
      "where n.nspname=$1 and p.proname=$2",[target.schema,target.name]);
    for(const row of functions.rows)
      if(!row.can_alter&&!(activeRole===row.owner.toLowerCase()&&row.can_set)&&
          !plannedMembership.has(row.owner.toLowerCase()))
        throw Error("migration capability denied: "+login+" cannot alter "+row.signature+
          "; owner is "+row.owner);
  }
}
