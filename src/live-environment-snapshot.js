/** Offline comparison for Supabase SQL Editor environment exports. Never connects to a DB. */
const SECTIONS={
  roles:["rolname"],memberships:["member","parent"],schemas:["schema_name"],
  relations:["schema_name","name","relkind"],
  column_acls:["schema_name","table_name","column_name"],
  functions:["schema_name","name","arguments"],
  policies:["schemaname","tablename","policyname"],
  default_acls:["owner","schema_name","kind"],extensions:["extname"]
};
const PRIVILEGE=new Set(["roles","memberships","schemas","relations","column_acls","functions","default_acls","database_acl"]);
const COMPATIBILITY=new Set(["policies","extensions","postgres_version"]);
function parseCsvCell(source){
  const text=source.replace(/^\uFEFF/,"");
  const start=text.indexOf("\n");
  if(start<0)throw Error("CSV requires a header and a JSON row");
  const label=text.slice(0,start).trim();
  if(label!=="complete_snapshot"&&label!=="snapshot_json")throw Error("Unexpected SQL Editor column: "+label);
  let i=start+1,value="",closed=false;
  if(text[i++]!=='"')throw Error("Expected quoted JSON CSV cell");
  while(i<text.length){
    const ch=text[i++];
    if(ch==='"'){
      if(text[i]==='"'){value+='"';i++;}
      else {closed=true;break;}
    }else value+=ch;
  }
  if(!closed||text.slice(i).trim())throw Error("CSV must contain exactly one JSON row");
  return value;
}
export function parseLiveEnvironmentSnapshot(contents){
  if(typeof contents!=="string"||!contents.trim())throw Error("Empty snapshot file");
  let snapshot=JSON.parse(contents.trimStart().startsWith("{")?contents:parseCsvCell(contents));
  if(snapshot?.complete_snapshot!==undefined)snapshot=snapshot.complete_snapshot;
  if(snapshot?.snapshot_json!==undefined)snapshot=snapshot.snapshot_json;
  if(typeof snapshot==="string")snapshot=JSON.parse(snapshot);
  if(!snapshot||typeof snapshot!=="object"||Array.isArray(snapshot)||
    typeof snapshot.postgres_version!=="string"||!Array.isArray(snapshot.migration_ledger))
    throw Error("Expected complete snapshot with PostgreSQL version and migration_ledger");
  for(const section of Object.keys(SECTIONS))
    if(!Array.isArray(snapshot[section]))throw Error("Missing snapshot section: "+section);
  for(const row of snapshot.migration_ledger)
    if(["version","name","checksum","source"].some(key=>typeof row[key]!=="string"))
      throw Error("Invalid migration ledger row");
  if(snapshot.snapshot_format==="ztribe-supabase-kit-v2"){
    if(!["chat","indexer"].includes(snapshot.project)||snapshot.pg_major!==17)
      throw Error("Invalid v2 snapshot project or PostgreSQL major");
    if(!Array.isArray(snapshot.schemas_requested)||!snapshot.schemas_requested.length||
       !Array.isArray(snapshot.schemas_missing)||snapshot.schemas_missing.length)
      throw Error("Missing requested schema in v2 snapshot");
    const structural=snapshot.structural_catalog;
    for(const key of ["tables","columns","constraints","indexes","triggers","functions","policies","publications"])
      if(!Array.isArray(structural?.[key]))throw Error("Incomplete v2 structural catalog: "+key);
    const present=new Set(snapshot.schemas.map(x=>x.schema_name));
    for(const schema of snapshot.schemas_requested)
      if(!present.has(schema))throw Error("Requested schema absent in v2 snapshot: "+schema);
  }
  return snapshot;
}
/** Map the full Supabase SQL Editor v2 export into the existing Kit pre-draft schema. */
export function liveSnapshotToKitTargetState(snapshot) {
  if(snapshot?.snapshot_format!=="ztribe-supabase-kit-v2")
    throw Error("Only v2 full snapshots can become pre-draft context");
  // Reuse the strict parser checks instead of accepting partial catalogs.
  const captured=parseLiveEnvironmentSnapshot(JSON.stringify(snapshot));
  return {
    version:1,
    schema:captured.structural_catalog,
    permissions:{
      schemas:captured.schemas.map(({schema_name,owner,acl})=>({schema:schema_name,owner,acl})),
      objects:captured.relations.map(({schema_name,name,relkind,owner,rls,force_rls,acl})=>
        ({schema:schema_name,name,kind:relkind,owner,rls,force_rls,acl})),
      functions:captured.functions.map(({schema_name,name,arguments:identityArgs,owner,
        security_definer, function_settings,acl})=>({schema:schema_name,name,arguments:identityArgs,
        owner,security_definer,configuration:function_settings,acl})),
      columnPrivileges:captured.column_acls.map(({schema_name,table_name,column_name,acl})=>
        ({schema:schema_name,relation:table_name,column_name,acl})),
      policies:captured.policies.map(({schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check})=>
        ({schema:schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check})),
      roles:captured.roles,
      memberships:captured.memberships,
      defaultPrivileges:captured.default_acls.map(({owner,schema_name,kind,acl})=>
        ({owner,schema:schema_name,kind,acl})),
      databasePrivileges:[{scope:"current",owner:captured.database_acl?.owner??null,
        acl:captured.database_acl?.acl??null}]
    },
    sourceInfo:{kind:"SUPABASE_SQL_EDITOR_SNAPSHOT",source:captured.project,
      collectedAt:captured.collected_at??null,
      newestLedger:captured.migration_ledger.at(-1)?.version??null,
      schemas:captured.schemas_requested}
  };
}
function stable(value){
  if(Array.isArray(value))return value.map(stable);
  if(value&&typeof value==="object")return Object.fromEntries(Object.entries(value)
    .sort(([a],[b])=>a.localeCompare(b)).map(([key,item])=>[key,stable(item)]));
  return value;
}
function keyOf(row,fields){
  if(!row||typeof row!=="object"||fields.some(field=>row[field]===undefined||row[field]===null))
    throw Error("Missing snapshot identity field: "+fields.join(","));
  return fields.map(field=>String(row[field])).join(" / ");
}
function keyed(rows,fields,section){
  if(!Array.isArray(rows))throw Error("Missing snapshot array: "+section);
  const out=new Map();
  for(const row of rows){
    const key=keyOf(row,fields);
    if(out.has(key))throw Error("Duplicate "+section+" identity: "+key);
    out.set(key,row);
  }
  return out;
}
function fieldsChanged(a,b){
  return [...new Set([...Object.keys(a??{}),...Object.keys(b??{})])].filter(key=>
    JSON.stringify(stable(a?.[key]))!==JSON.stringify(stable(b?.[key]))).sort();
}
function finding(section,key,a,b,level){
  // Never print raw function settings, policy expressions, or other potentially sensitive values.
  return {section,key,kind:a&&b?"changed":a?"dev_only":"production_only",
    severity:level??(PRIVILEGE.has(section)?"permission_review":
      COMPATIBILITY.has(section)?"compatibility_review":"review"),
    fields:fieldsChanged(a,b)};
}
export function compareLiveEnvironmentSnapshots(dev,production){
  if(!dev||!production)throw Error("Dev and Production snapshots are required");
  const findings=[];
  for(const [section,fields] of Object.entries(SECTIONS)){
    const before=keyed(dev[section],fields,section);
    const after=keyed(production[section],fields,section);
    for(const key of [...new Set([...before.keys(),...after.keys()])].sort()){
      const a=before.get(key),b=after.get(key);
      if(JSON.stringify(stable(a))!==JSON.stringify(stable(b)))
        findings.push(finding(section,key,a,b));
    }
  }
  if(dev.postgres_version!==production.postgres_version)
    findings.push({section:"postgres_version",key:"server",kind:"changed",
      severity:"compatibility_review",fields:["postgres_version"]});
  if(JSON.stringify(stable(dev.database_acl))!==JSON.stringify(stable(production.database_acl)))
    findings.push(finding("database_acl","current_database",dev.database_acl,production.database_acl));
  const before=keyed(dev.migration_ledger,["version"],"migration_ledger");
  const after=keyed(production.migration_ledger,["version"],"migration_ledger");
  // Dev can legitimately be ahead of Production. This is a pending upgrade,
  // not a checksum mismatch. A missing middle version or Production-ahead
  // history is not automatically safe and remains a blocker.
  const devHasProductionPrefix=production.migration_ledger.length>0 &&
    production.migration_ledger.every((p,i)=>dev.migration_ledger[i]?.version===p.version);
  for(const version of [...new Set([...before.keys(),...after.keys()])].sort()){
    const a=before.get(version),b=after.get(version);
    if(!a||!b){
      const expectedDevSuffix=Boolean(a&&!b&&devHasProductionPrefix);
      findings.push(finding("migration_ledger",version,a,b,
        expectedDevSuffix?"upgrade_pending":"migration_blocker"));
    }else if(a.name!==b.name||a.checksum!==b.checksum)
      findings.push(finding("migration_ledger",version,a,b,"migration_blocker"));
    else if(a.source!==b.source)
      findings.push({section:"migration_ledger",key:version,kind:"source_different",
        severity:"information",fields:["source"]});
    // applied_at never indicates SQL drift.
  }
  const levels=["migration_blocker","compatibility_review","permission_review","upgrade_pending","review","information"];
  const counts=Object.fromEntries(levels.map(level=>[level,
    findings.filter(item=>item.severity===level).length]));
  return {schema_version:1,
    status:counts.migration_blocker?"block":
      counts.compatibility_review||counts.permission_review||counts.upgrade_pending||counts.review?"review":"aligned",
    counts,migration_counts:{dev:dev.migration_ledger.length,production:production.migration_ledger.length},
    findings,limitations:[
      "SQL Editor login may not match the Railway migration login.",
      "Docker postgres superuser differs from Supabase postgres.",
      "This report compares snapshots; it does not replay role privileges or verify data."
    ]};
}
