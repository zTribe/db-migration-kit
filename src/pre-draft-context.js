/** Advisory facts for migration authors, never approval to modify a database. */
import { createHash } from "node:crypto";
const digest = obj => createHash("sha256").update(JSON.stringify(obj)).digest("hex");
const ID = /^[a-z_][a-z0-9_]*$/;
export function parsePreDraftTarget(spec) {
  if(typeof spec!=="string")throw Error("Target must be a string");
  const m=/^(relation|function):([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)(?:\((.*)\))?$/.exec(spec);
  if(!m || (m[1]==="relation"&&m[4]!==undefined))throw Error("Expected relation:schema.name or function:schema.name(args)");
  return {kind:m[1],schema:m[2],name:m[3],args:m[4]??null};
}
const argsKey = s=>String(s??"").trim().toLowerCase().replace(/\s+/g," ");
export function buildPreDraftContext({project,snapshot,profile,targets,ownerPolicy={},migrationName=null,snapshotSource="expected-target",baselineChecked=false,operation="modify"}={}) {
  if(!["chat","indexer"].includes(project))throw Error("Unknown project");
  if(!snapshot?.permissions || !["schemas","objects","functions"].every(k=>Array.isArray(snapshot.permissions[k])))throw Error("Kit permissions catalog required");
  if(profile?.project!==project || profile.source!=="production" || profile.postgresMajor!==17 ||
    !Array.isArray(profile.schemas)||!Array.isArray(profile.roles)||!Array.isArray(profile.memberships)||
    !profile.roles.some(r=>r.rolname===profile.migrationRole&&r.rolsuper===false))throw Error("Realistic non-superuser project profile required");
  if(!Array.isArray(targets)||!targets.length)throw Error("At least one target is required");
  if(!["expected-target","provided-snapshot"].includes(snapshotSource))throw Error("Unknown snapshot source");
  if(!["create","modify"].includes(operation))throw Error("Unknown DDL operation");
  const issues=[],objects=[],unique=new Set();
  const issue=(severity,code,target,detail)=>issues.push({severity,code,target,detail});
  for(const text of targets) {
    const t=typeof text==="string"?parsePreDraftTarget(text):text;
    if(!["relation","function"].includes(t?.kind)||!ID.test(t.schema??"")||!ID.test(t.name??"")||
       (t.args!=null&&(typeof t.args!=="string"||t.args.length>300)))throw Error("Invalid target");
    const label=t.kind+":"+t.schema+"."+t.name+(t.args===null?"":"("+t.args+")");
    if(unique.has(label))throw Error("Duplicate pre-draft target "+label);
    unique.add(label);
    const schema=snapshot.permissions.schemas.find(x=>x.schema===t.schema)??null;
    const covered=profile.schemas.includes(t.schema);
    const all=(t.kind==="function"?snapshot.permissions.functions:snapshot.permissions.objects)
      .filter(x=>x.schema===t.schema&&x.name===t.name&&(t.kind!=="relation"||x.kind!=="S"));
    const matches=t.kind==="function"&&t.args!==null?all.filter(x=>argsKey(x.arguments)===argsKey(t.args)):all;
    const obj=matches.length===1?matches[0]:null;
    const owner=obj?.owner??null;
    const member=owner?profile.memberships.find(x=>x.member===profile.migrationRole&&x.parent===owner):null;
    if(!schema)issue("block","SCHEMA_UNKNOWN",label,"Schema missing in supplied catalog");
    if(!covered)issue("block","PROFILE_SCHEMA_UNCOVERED",label,"Recorded Production profile does not cover schema");
    if(!matches.length&&operation!=="create")issue("block","OBJECT_UNKNOWN",label,"Object not found; verify creation intent or stale catalog");
    if(matches.length&&operation==="create")issue("block","OBJECT_ALREADY_EXISTS",label,"Object already exists in catalog; choose modify instead of create");
    if(!matches.length&&operation==="create")issue("review","NEW_OBJECT_UNVERIFIED",label,"New object is not in recorded catalog; verify schema CREATE privilege and name collisions");
    if(matches.length>1)issue("block","OVERLOADED_OR_AMBIGUOUS",label,"Specify exact function identity arguments");
    if(obj&&owner!==profile.migrationRole)issue("review","OWNER_MISMATCH",label,"Owner differs from migration role; verify actual SET/ADMIN/INHERIT or scoped Kit recipe");
    if(obj?.security_definer&&!(obj.configuration??[]).some(x=>String(x).startsWith("search_path=")))
      issue("review","DEFINER_PATH_MISSING",label,"SECURITY DEFINER lacks recorded fixed search_path");
    // Reuse the existing Kit readSchemaCatalogOnClient snapshot. Never
    // infer missing columns or indexes from a permissions-only target.
    const structure=snapshot.schema;
    const related=key=>Array.isArray(structure?.[key])?structure[key].filter(x=>
      x.schema_name===t.schema && (t.kind==="relation" ? x.table_name===t.name : x.name===t.name)) : [];
    const definition=t.kind==="relation" ? {
      columns:related("columns"),
      constraints:related("constraints"),
      indexes:related("indexes"),
      triggers:related("triggers"),
      table:structure?.tables?.find(x=>x.schema_name===t.schema&&x.name===t.name)??null,
    } : {overloads:related("functions")};
    objects.push({target:label,operation,matched:matches.length,profileCoversSchema:covered,
      availableSignatures:t.kind==="function"?all.map(x=>x.arguments):[],
      schemaOwner:schema?.owner??null,schemaAcl:schema?.acl??null,
      structuralCatalog:structure?definition:null,
      recordedObject:obj?{owner,arguments:obj.arguments??null,kind:obj.kind??"function",
        acl:obj.acl??null,rls:obj.rls??null,forceRls:obj.force_rls??null,
        securityDefiner:obj.security_definer??null,configuration:obj.configuration??null}:null,
      recordedMembership:owner?{sameAsMigrator:owner===profile.migrationRole,
        admin:member?.admin_option??null,set:member?.set_option??null,inherit:member?.inherit_option??null}:null,
      policies:t.kind==="relation"?(snapshot.permissions.policies??[])
        .filter(p=>p.schema===t.schema&&p.tablename===t.name):[],
      possibleOwnerRecipes:t.kind==="function"?(ownerPolicy?.recipes??[]).filter(r=>
        r.schema===t.schema&&r.functionName===t.name&&(!migrationName||r.name===migrationName))
        .map(r=>({name:r.name,mode:r.mode,role:r.role,reviewRequired:true})):[],
      authority:"AUTHORING_EVIDENCE_ONLY"});
  }
  const migrator=profile.roles.find(r=>r.rolname===profile.migrationRole);
  if(migrator.rolbypassrls===true)issue("review","MIGRATOR_BYPASSES_RLS","project","Recorded migration login has BYPASSRLS; test runtime roles separately for actual RLS enforcement");
  issue("review","LIVE_LEDGER_UNVERIFIED","project","Check actual Dev/Prod ledger, checksum and database identity read-only");
  issue("review","TARGET_ROLE_UNVERIFIED","project","Check actual migration login DDL capabilities and real PG17 replay");
  if(snapshot.schema===null)issue("review","SCHEMA_DEFINITIONS_MISSING","project","Permission-only snapshot lacks columns/indexes/constraints");
  if(snapshotSource==="expected-target")issue("review","EXPECTED_NOT_LIVE","project","migration-target.json is expected catalog, not live database proof");
  return {kind:"KIT_AI_PRE_DRAFT_CONTEXT",approved:false,releaseApproved:false,project,migrationName,
    snapshotSource,operation,recordedMigrationRole:profile.migrationRole,permissionBaseline:profile.baseline??null,
    baselineChecked,blocked:issues.some(x=>x.severity==="block"),objects,issues,
    provenance:{snapshotSha256:digest(snapshot),profileSha256:digest(profile)},
    next:"Review unknowns and application consumers before SQL; afterwards Kit draft-check and disposable PG17 prepare are mandatory."};
}
