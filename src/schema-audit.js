/**
 * Structural schema catalog, deliberately separate from runtime permission
 * policies. Snapshot normalization compares checked-out expected structure
 * against live PostgreSQL catalogs, including functions and publications.
 */
const SQL=`
WITH tables AS (
 SELECT n.nspname AS schema_name, c.relname AS name, c.relkind AS kind,
        c.relrowsecurity AS rls, c.relforcerowsecurity AS force_rls
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=ANY($1::text[]) AND c.relkind IN ('r','p','v','m','S','f')
), columns AS (
 SELECT n.nspname AS schema_name,c.relname AS table_name,a.attname AS name,
        pg_catalog.format_type(a.atttypid,a.atttypmod) AS type,
        a.attnotnull AS not_null, a.attidentity AS identity,
        a.attgenerated AS generated,
        pg_catalog.pg_get_expr(d.adbin,d.adrelid) AS default_expr
 FROM pg_catalog.pg_attribute a
 JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE n.nspname=ANY($1::text[]) AND c.relkind IN ('r','p','v','m','f')
  AND a.attnum>0 AND NOT a.attisdropped
), constraints AS (
 SELECT n.nspname AS schema_name,c.relname AS table_name,
        con.conname AS name, con.contype AS kind,
        pg_catalog.pg_get_constraintdef(con.oid,true) AS definition
 FROM pg_catalog.pg_constraint con JOIN pg_catalog.pg_class c ON c.oid=con.conrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=ANY($1::text[])
), indexes AS (
 SELECT n.nspname AS schema_name,c.relname AS table_name,ic.relname AS name,
        ix.indisvalid AS valid,ix.indisready AS ready,
        pg_catalog.pg_get_indexdef(ix.indexrelid) AS definition
 FROM pg_catalog.pg_index ix JOIN pg_catalog.pg_class c ON c.oid=ix.indrelid
 JOIN pg_catalog.pg_class ic ON ic.oid=ix.indexrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=ANY($1::text[])
), triggers AS (
 SELECT n.nspname AS schema_name,c.relname AS table_name,t.tgname AS name,
        t.tgenabled AS enabled,pg_catalog.pg_get_triggerdef(t.oid) AS definition
 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=ANY($1::text[]) AND NOT t.tgisinternal
), functions AS (
 SELECT n.nspname AS schema_name,p.proname AS name,
        pg_catalog.pg_get_function_identity_arguments(p.oid) AS args,
        pg_catalog.pg_get_function_result(p.oid) AS result,
        p.prokind AS kind,p.prosecdef AS security_definer,
        p.proconfig AS settings,pg_catalog.pg_get_functiondef(p.oid) AS definition
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname=ANY($1::text[]) AND p.prokind IN ('f','p')
), policies AS (
 SELECT n.nspname AS schema_name,c.relname AS table_name,p.polname AS name,
        p.polcmd AS command,p.polpermissive AS permissive,
        ARRAY(SELECT CASE WHEN x.role_id=0::oid THEN 'PUBLIC' ELSE r.rolname END
          FROM pg_catalog.unnest(p.polroles) x(role_id)
          LEFT JOIN pg_catalog.pg_roles r ON r.oid=x.role_id ORDER BY 1)::text[] AS roles,
        pg_catalog.pg_get_expr(p.polqual,p.polrelid) AS using_expr,
        pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) AS check_expr
 FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=ANY($1::text[])
), publications AS (
 SELECT p.pubname AS name,p.puballtables AS all_tables,
        p.pubinsert AS insert_enabled,p.pubupdate AS update_enabled,
        p.pubdelete AS delete_enabled,p.pubtruncate AS truncate_enabled,
        coalesce((
          SELECT jsonb_agg(n.nspname||'.'||c.relname ORDER BY n.nspname,c.relname)
          FROM pg_catalog.pg_publication_rel pr
          JOIN pg_catalog.pg_class c ON c.oid=pr.prrelid
          JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
          WHERE pr.prpubid=p.oid AND n.nspname=ANY($1::text[])
        ),'[]'::jsonb) AS tables
 FROM pg_catalog.pg_publication p
 WHERE p.puballtables OR EXISTS (
   SELECT 1 FROM pg_catalog.pg_publication_rel pr
   JOIN pg_catalog.pg_class c ON c.oid=pr.prrelid
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE pr.prpubid=p.oid AND n.nspname=ANY($1::text[])
 )
)
SELECT
 coalesce((SELECT jsonb_agg(to_jsonb(t)) FROM tables t),'[]'::jsonb) AS tables,
 coalesce((SELECT jsonb_agg(to_jsonb(x)) FROM columns x),'[]'::jsonb) AS columns,
 coalesce((SELECT jsonb_agg(to_jsonb(x)) FROM constraints x),'[]'::jsonb) AS constraints,
 coalesce((SELECT jsonb_agg(to_jsonb(x)) FROM indexes x),'[]'::jsonb) AS indexes,
 coalesce((SELECT jsonb_agg(to_jsonb(x)) FROM triggers x),'[]'::jsonb) AS triggers,
 coalesce((SELECT jsonb_agg(to_jsonb(x)) FROM functions x),'[]'::jsonb) AS functions,
 coalesce((SELECT jsonb_agg(to_jsonb(x)) FROM policies x),'[]'::jsonb) AS policies,
 coalesce((SELECT jsonb_agg(to_jsonb(x)) FROM publications x),'[]'::jsonb) AS publications
`;

const SORT_KEYS={
 tables:r=>`${r.schema_name}.${r.name}`,
 columns:r=>`${r.schema_name}.${r.table_name}.${r.name}`,
 constraints:r=>`${r.schema_name}.${r.table_name}.${r.name}`,
 indexes:r=>`${r.schema_name}.${r.name}`,
 triggers:r=>`${r.schema_name}.${r.table_name}.${r.name}`,
 functions:r=>`${r.schema_name}.${r.name}(${r.args})`,
 policies:r=>`${r.schema_name}.${r.table_name}.${r.name}`,
 publications:r=>r.name,
};
export function normalizeSchemaCatalog(value){
  if(!value || typeof value!=="object")throw new Error("invalid structure catalog");
  return Object.fromEntries(Object.entries(SORT_KEYS).map(([kind,key])=>{
    if(!Array.isArray(value[kind]))throw new Error(`missing catalog section: ${kind}`);
    const list=value[kind].map(row=>structuredClone(row));
    list.sort((a,b)=>key(a).localeCompare(key(b)));
    return [kind,list];
  }));
}
export async function readSchemaCatalog(pool,schemas,{statementTimeoutMs=10000}={}){
  if(!Array.isArray(schemas)||!schemas.length||schemas.some(s=>typeof s!=="string"||!s))
    throw new Error("nonempty schema name list required");
  const client=await pool.connect();let active=false;
  try{
    await client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");active=true;
    await client.query("SELECT pg_catalog.set_config('statement_timeout',$1,true)",[String(statementTimeoutMs)]);
    const result=await client.query(SQL,[schemas]);
    const snapshot=normalizeSchemaCatalog(result.rows[0]);
    await client.query("COMMIT");active=false;return snapshot;
  }catch(error){if(active)await client.query("ROLLBACK").catch(()=>{});throw error}
  finally{client.release()}
}
export function compareSchemaCatalog(expected,actual){
  const left=normalizeSchemaCatalog(expected),right=normalizeSchemaCatalog(actual);
  const differences=[];
  for(const [section,key] of Object.entries(SORT_KEYS)){
    const old=new Map(left[section].map(x=>[key(x),x]));
    const current=new Map(right[section].map(x=>[key(x),x]));
    for(const [name,desired] of old){
      if(!current.has(name))differences.push({section,key:name,code:"MISSING"});
      else if(JSON.stringify(desired)!==JSON.stringify(current.get(name)))
        differences.push({section,key:name,code:"CHANGED",expected:desired,actual:current.get(name)});
    }
    for(const name of current.keys())if(!old.has(name))differences.push({section,key:name,code:"UNEXPECTED"});
  }
  return {ok:differences.length===0,differences};
}
export async function auditSchemaCatalog(pool,{schemas,expected}){
  const actual=await readSchemaCatalog(pool,schemas);
  return {...compareSchemaCatalog(expected,actual),actual};
}
