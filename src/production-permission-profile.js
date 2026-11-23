import { createHash } from "node:crypto";
const VALID=/^[a-z_][a-z_0-9]*$/;
const FLAG=["rolcanlogin","rolsuper","rolcreatedb","rolcreaterole","rolbypassrls","rolinherit","rolreplication"];
const SECTIONS=["relations","functions","column_acls","policies"];
const FIELDS={
 relations:["schema_name","name","relkind","owner","rls","force_rls","acl"],
 functions:["schema_name","name","arguments","owner","security_definer","function_settings","acl"],
 column_acls:["schema_name","table_name","column_name","acl"],
 policies:["schemaname","tablename","policyname","permissive","roles","cmd","using_hash","check_hash"]
};
function acl(value){
 if(value==null)return null;
 if(Array.isArray(value))return [...value].sort();
 if(typeof value!=="string"||!value.startsWith("{")||!value.endsWith("}"))
  throw Error("Invalid PG ACL literal");
 const body=value.slice(1,-1);
 if(body.includes('"')||body.includes("\\"))throw Error("Quoted ACL requires reviewed parser");
 return body?body.split(",").sort():[];
}
const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==="object"
 ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])])):value;
const json=value=>JSON.stringify(stable(value));
function pickRows(rows,section){
 return rows.map(row=>Object.fromEntries(FIELDS[section].map(field=>[
  field,field==="acl"?acl(row[field]):Array.isArray(row[field])?[...row[field]].sort():row[field]??null
 ]))).sort((a,b)=>json(a)<json(b)?-1:json(a)>json(b)?1:0);
}
function digest(rows){
 return {count:rows.length,sha256:createHash("sha256").update(json(rows)).digest("hex")};
}
export function projectPermissionCatalog(state,schemas){
 const scope=new Set(schemas);
 const normalize=section=>state[section].filter(row=>scope.has(row.schema_name??row.schemaname));
 return Object.fromEntries(SECTIONS.map(section=>[section,digest(pickRows(normalize(section),section))]));
}
/** Convert a Supabase SQL Editor export into a small production-only, non-secret fixture. */
export function deriveProductionPermissionProfile(snapshot,{project,schemas,roles,migrationRole="postgres"}){
 if(!["chat","indexer"].includes(project)||!Array.isArray(schemas)||!schemas.length||
  !Array.isArray(roles)||!roles.includes(migrationRole)||
  [...schemas,...roles,migrationRole].some(name=>!VALID.test(name)))
  throw Error("Explicit project, schemas and scoped role names required");
 if(Number(/^(\d+)/.exec(snapshot.postgres_version??"")?.[1])!==17)
  throw Error("PG17 production snapshot required");
 const names=[...new Set(roles)].sort(),scope=[...new Set(schemas)].sort();
 const roleRows=names.map(name=>{
  const row=snapshot.roles.find(x=>x.rolname===name);
  if(!row)throw Error("Production role missing: "+name);
  return {rolname:name,...Object.fromEntries(FLAG.map(flag=>[flag,row[flag]]))};
 });
 const membership=snapshot.memberships.filter(row=>names.includes(row.member)&&names.includes(row.parent))
  .map(row=>({member:row.member,parent:row.parent,admin_option:row.admin_option===true,
   inherit_option:row.inherit_option===true||row.inherit_option==="true",
   set_option:row.set_option===true||row.set_option==="true"}))
  .sort((a,b)=>json(a)<json(b)?-1:json(a)>json(b)?1:0);
 const schemaRights=scope.map(name=>{
  const row=snapshot.schemas.find(x=>x.schema_name===name);
  if(!row)throw Error("Production schema missing: "+name);
  return {name,owner:row.owner,acl:acl(row.acl)};
 });
 const ledger=snapshot.migration_ledger;
 if(!Array.isArray(ledger)||!ledger.length||
  ledger.some((row,i)=>typeof row.version!=="string"||typeof row.checksum!=="string"||
   (i>0&&ledger[i-1].version>=row.version)))
  throw Error("Production snapshot requires sorted immutable migration ledger");
 const latest=ledger.at(-1);
 const baseline={version:latest.version,checksum:latest.checksum,count:ledger.length};
 const dbEntries=acl(snapshot.database_acl?.acl)??[];
 const dbRights={owner:snapshot.database_acl?.owner,acl:dbEntries.filter(entry=>{
  const member=entry.split("=")[0];return !member||names.includes(member);
 })};
 return {schemaVersion:1,project,source:"production",migrationRole,postgresMajor:17,
  schemas:scope,roles:roleRows,memberships:membership,
  schemaRights,databaseRights:dbRights,baseline,
  catalog:projectPermissionCatalog(snapshot,scope)};
}
/** Adapt the shared Kit's real PostgreSQL permission-state query to the export format. */
/** Match exactly the columns and hashes in the operator's Supabase SQL Editor export.
 * readPermissionState() alone lacks function definition hashes and cannot prove parity. */
async function readProductionCatalog(client,schemas,roles,project){
 const query=async(sql,params=[])=> (await client.query(sql,params)).rows;
 const postgres_version=(await query("SELECT current_setting('server_version') AS v"))[0].v;
 const roleRows=await query(
  "SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,rolinherit,rolreplication FROM pg_catalog.pg_roles WHERE rolname=ANY($1::text[])",[roles]);
 const memberships=await query(
  "SELECT member.rolname AS member,parent.rolname AS parent,a.admin_option,a.inherit_option,a.set_option FROM pg_catalog.pg_auth_members a JOIN pg_catalog.pg_roles member ON member.oid=a.member JOIN pg_catalog.pg_roles parent ON parent.oid=a.roleid WHERE member.rolname=ANY($1::text[]) AND parent.rolname=ANY($1::text[])",[roles]);
 const schemasRows=await query(
  "SELECT nspname AS schema_name,pg_catalog.pg_get_userbyid(nspowner) AS owner,nspacl::text AS acl FROM pg_catalog.pg_namespace WHERE nspname=ANY($1::text[])",[schemas]);
 const relations=await query(
  "SELECT n.nspname AS schema_name,c.relname AS name,c.relkind,pg_catalog.pg_get_userbyid(c.relowner) AS owner,c.relrowsecurity AS rls,c.relforcerowsecurity AS force_rls,c.relacl::text AS acl FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY($1::text[]) AND c.relkind IN ('r','p','v','m','f','S')",[schemas]);
 const column_acls=await query(
  "SELECT n.nspname AS schema_name,c.relname AS table_name,a.attname AS column_name,a.attacl::text AS acl FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY($1::text[]) AND a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL",[schemas]);
 const functions=await query(
  "SELECT n.nspname AS schema_name,p.proname AS name,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,pg_catalog.pg_get_userbyid(p.proowner) AS owner,p.prosecdef AS security_definer,p.proconfig AS function_settings,p.proacl::text AS acl,md5(pg_catalog.pg_get_functiondef(p.oid)) AS definition_hash FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=ANY($1::text[]) AND p.prokind IN ('f','p')",[schemas]);
 const policies=await query(
  // pg_policies.roles is name[] (OID 1003); node-postgres does not parse it
  // into JS arrays by default. Cast to text[] (OID 1009), which its built-in
  // parser decodes to the same array shape as Supabase JSON exports.
  "SELECT schemaname,tablename,policyname,permissive,roles::text[] AS roles,cmd,md5(coalesce(qual,'')) AS using_hash,md5(coalesce(with_check,'')) AS check_hash FROM pg_catalog.pg_policies WHERE schemaname=ANY($1::text[])",[schemas]);
 const ledgerSchema=project==="chat"?"app":project==="indexer"?"chain":null;
 if(!ledgerSchema)throw Error("Invalid Production project");
 const migration_ledger=await query(
  "SELECT version,checksum,name,source FROM "+ledgerSchema+".schema_migrations ORDER BY version");
 const database_acl=(await query(
  "SELECT pg_catalog.pg_get_userbyid(datdba) AS owner,datacl::text AS acl FROM pg_catalog.pg_database WHERE datname=current_database()"))[0];
 return {postgres_version,roles:roleRows,memberships,schemas:schemasRows,
  relations,column_acls,functions,policies,database_acl,migration_ledger};
}
export function compareProductionPermissionProfiles(expected,actual){
 if(expected.schemaVersion!==1||actual.schemaVersion!==1||expected.project!==actual.project)
  throw Error("Production permission profile format/project mismatch");
 const checks=["postgresMajor","migrationRole","schemas","roles","memberships","schemaRights","databaseRights","baseline"];
 const findings=checks.filter(k=>json(expected[k])!==json(actual[k])).map(k=>({section:k,reason:"production_mismatch"}));
 for(const section of SECTIONS)
  if(json(expected.catalog[section])!==json(actual.catalog[section]))
   findings.push({section,reason:"production_catalog_mismatch",expectedCount:expected.catalog[section].count,
    actualCount:actual.catalog[section].count});
 return {ok:findings.length===0,findings,
  limitations:"Supabase extensions and actual Railway migration login require independent verification"};
}
export function assertProductionPermissionProfile(profile,state){
 const actual=deriveProductionPermissionProfile(state,{
  project:profile.project,schemas:profile.schemas,
  roles:profile.roles.map(x=>x.rolname),migrationRole:profile.migrationRole});
 const report=compareProductionPermissionProfiles(profile,actual);
 if(!report.ok)throw Error("Docker catalog differs from Production: "+JSON.stringify(report.findings));
 return report;
}
export async function verifyProductionPermissionFixture(client,profile){
 // The caller must run this on a disposable PG17 database AFTER historical replay.
 // This function is strictly read-only, including the database session.
 await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
 try{
  const major=(await client.query("SELECT current_setting('server_version_num')::integer / 10000 AS major")).rows[0]?.major;
  if(major!==profile.postgresMajor)throw Error("Postgres major mismatch: expected "+profile.postgresMajor+", got "+major);
  const state=await readProductionCatalog(client,profile.schemas,profile.roles.map(x=>x.rolname),profile.project);
  return assertProductionPermissionProfile(profile,state);
 } finally {await client.query("ROLLBACK")}
}
/** Generates fixture-only DDL; the Kit never executes privilege-changing SQL on production. */
export function renderDisposableRoleSetup(profile){
 if(profile.schemaVersion!==1||!profile.roles?.length)throw Error("Invalid production fixture");
 const q=name=>{if(!VALID.test(name))throw Error("Unsafe role name");return '"'+name+'"';};
 const sql=[];
 for(const role of profile.roles){
  if(role.rolsuper)throw Error("SUPERUSER production profile forbidden");
  const opts=[["rolcanlogin","LOGIN","NOLOGIN"],["rolsuper","SUPERUSER","NOSUPERUSER"],
   ["rolcreatedb","CREATEDB","NOCREATEDB"],["rolcreaterole","CREATEROLE","NOCREATEROLE"],
   ["rolbypassrls","BYPASSRLS","NOBYPASSRLS"],["rolinherit","INHERIT","NOINHERIT"],
   ["rolreplication","REPLICATION","NOREPLICATION"]].map(([k,t,f])=>{
    if(typeof role[k]!=="boolean")throw Error("Invalid role option "+k);
    return role[k]?t:f;
   });
  // Role bootstrap and demotion must run as a separate disposable Docker superuser.
  sql.push("DO $kit_role$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '"+
    role.rolname+"') THEN CREATE ROLE "+q(role.rolname)+" NOLOGIN; END IF; END $kit_role$;");
  sql.push("ALTER ROLE "+q(role.rolname)+" "+opts.join(" ")+";");
 }
 for(const m of profile.memberships){
  // Remove any historical, possibly more permissive membership before replaying
  // the reviewed Production ADMIN/INHERIT/SET options in the disposable fixture.
  sql.push("REVOKE "+q(m.parent)+" FROM "+q(m.member)+";");
 }
 for(const m of profile.memberships)sql.push("GRANT "+q(m.parent)+" TO "+q(m.member)+
  " WITH ADMIN "+(m.admin_option?"TRUE":"FALSE")+", INHERIT "+(m.inherit_option?"TRUE":"FALSE")+
  ", SET "+(m.set_option?"TRUE":"FALSE")+";");
 return sql.join("\n")+"\n";
}

/** Deterministic fixture ACL SQL. Pure generator: never executes or connects online. */
export function renderDisposableAclSetup(profile){
 if(profile.schemaVersion!==1||!["production","dev"].includes(profile.source))
  throw Error("A reviewed Dev or Production checkpoint fixture is required");
 const id=name=>{if(!VALID.test(name))throw Error("Unsafe fixture ACL identifier");return '"'+name+'"';};
 const parse=entry=>{
  const match=/^([a-z_0-9]*)=([a-zA-Z]+)\/([a-z_][a-z0-9_]*)$/.exec(entry);
  if(!match)throw Error("Unsupported fixture ACL entry");
  return {who:match[1],flags:match[2],grantor:match[3]};
 };
 const lines=[];
 // Never use an online connection for this script. Run ONLY in a disposable
 // Docker PG17 container as a separately authenticated bootstrap superuser.
 for(const entry of profile.databaseRights.acl){
  const {who,flags}=parse(entry);
  const grantee=who?id(who):"PUBLIC";
  const rights=flags.split("").map(ch=>({C:"CREATE",T:"TEMPORARY",c:"CONNECT"})[ch]);
  if(rights.some(x=>!x))throw Error("Unsupported database ACL flags");
  lines.push("DO $kit_db$ BEGIN EXECUTE format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM "+grantee+"',current_database()); END $kit_db$;");
  if(rights.length)lines.push("DO $kit_db$ BEGIN EXECUTE format('GRANT "+rights.join(",")+" ON DATABASE %I TO "+grantee+"',current_database()); END $kit_db$;");
 }
 const roles=profile.roles.map(r=>r.rolname);
 // Production explicitly omits DB CREATE for Indexer runtime; eliminate any
 // replay-only grant instead of silently keeping that stronger local privilege.
 for(const role of roles){
  if(profile.databaseRights.acl.some(x=>x.startsWith(role+"=")))continue;
  lines.push("DO $kit_db$ BEGIN EXECUTE format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM "+id(role)+"',current_database()); END $kit_db$;");
 }
 for(const s of profile.schemaRights){
  if(!VALID.test(s.name)||!VALID.test(s.owner)||!Array.isArray(s.acl))
   throw Error("Invalid schema fixture");
  const schema=id(s.name);
  lines.push("REVOKE ALL PRIVILEGES ON SCHEMA "+schema+" FROM PUBLIC;");
  for(const entry of s.acl){
   const {who,flags}=parse(entry),grantee=who?id(who):"PUBLIC";
   const rights=flags.split("").map(ch=>({U:"USAGE",C:"CREATE"})[ch]);
   if(rights.some(x=>!x))throw Error("Unsupported schema ACL flags");
   lines.push("REVOKE ALL PRIVILEGES ON SCHEMA "+schema+" FROM "+grantee+";");
   if(rights.length)lines.push("GRANT "+rights.join(",")+" ON SCHEMA "+schema+" TO "+grantee+";");
  }
  for(const role of roles){
   if(s.acl.some(x=>x.startsWith(role+"=")))continue;
   lines.push("REVOKE ALL PRIVILEGES ON SCHEMA "+schema+" FROM "+id(role)+";");
  }
 }
 return lines.join("\n")+"\n";
}
