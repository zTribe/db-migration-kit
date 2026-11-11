import { inventorySecurityObjects } from "./object-model.js";

const ROLE_MATRIX_KIND={schema:"schemas",table:"tables",column:"columns",function:"functions",sequence:"sequences"};
const PERMISSIONS={schema:["USAGE","CREATE"],table:["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER"],column:["SELECT","INSERT","UPDATE","REFERENCES"],function:["EXECUTE"],sequence:["USAGE","SELECT","UPDATE"]};

/**
 * Produce UNAPPROVED candidate policy from a real, post-migration catalog.
 * Source attribution is for the snapshot as a whole: PostgreSQL does not
 * record which historical SQL statement granted each ACL. We never invent a
 * per-object source file. Snapshot state may include accidental grants.
 */
export function generateCandidatePolicy(snapshot, options={}) {
  const provenance=options.provenance ?? {};
  if(!provenance.repository || !provenance.ref || !Array.isArray(provenance.migrationFiles))
    throw new Error("candidate policy requires repository, ref and migrationFiles provenance");
  const inventory=snapshot.inventory ?? inventorySecurityObjects(snapshot);
  const roles=options.roles ?? snapshot.roles.map(role=>role.rolname);
  const known=new Set(snapshot.roles.map(role=>role.rolname));
  for(const role of roles)if(!known.has(role)) throw new Error(`unknown candidate role: ${role}`);
  const policies=inventory.objects.map(object=>{
    const candidate={kind:object.kind,key:object.key,reviewStatus:"needs_review",
      source:{type:"post_migration_catalog",repository:provenance.repository,
        ref:provenance.ref,migrationFiles:[...provenance.migrationFiles],
        attribution:"aggregate_only"},
      reviewReasons:["Catalog reflects observed state, not approved least-privilege intent",
        "Cannot attribute effective privilege to one SQL migration from final catalog"]};
    for(const key of ["owner","rls","forceRls","securityDefiner","searchPath",
      "superuser","bypassRls","command","permissive","roles","using","check"]) {
      if(object[key]!==undefined && object[key]!==null) candidate[key]=object[key];
    }
    if(ROLE_MATRIX_KIND[object.kind]) {
      const group=ROLE_MATRIX_KIND[object.kind];
      const permissions={};
      for(const role of roles){
        const effective=snapshot.privileges?.[group]?.[role]?.[object.key];
        if(!effective)continue;
        permissions[role]=Object.fromEntries(PERMISSIONS[object.kind].filter(p=>typeof effective[p]==="boolean")
          .map(p=>[p,effective[p]?"allow":"deny"]));
      }
      if(Object.keys(permissions).length)candidate.privileges=permissions;
    }
    return candidate;
  });
  return {schemaVersion:1,status:"candidate_needs_review",
    generatedFrom:"real_post_migration_catalog",
    provenance:{...provenance,migrationFiles:[...provenance.migrationFiles]},
    objectPolicies:policies,
    warnings:["Do not promote this snapshot directly to an approved security policy",
      "Grant inheritance and DDL origin require independent review",
      "Dynamic migration SQL is represented by observed catalog state, not static parsing"]};
}

/** Prevent unreviewed output from being used as an enforcement policy. */
export function assertApprovedSecurityPolicy(policy) {
  if(policy?.status!=="approved" || policy.schemaVersion!==1)
    throw new Error("security policy is not approved; candidate snapshots cannot be enforced");
  for(const item of policy.objectPolicies ?? [])
    if(item.reviewStatus!=="approved")throw new Error(`security policy object ${item.kind}:${item.key} remains unreviewed`);
  return policy;
}
