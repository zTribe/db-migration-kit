/** Advisory RPC signature comparison for schema catalog snapshots.
 * Caller must capture real PostgreSQL before/after states. This cannot certify
 * SQL dependencies, behavioral compatibility, provenance, or release safety.
 */
const ensure=(ok,message)=>{if(!ok)throw Error("RPC contract audit: "+message)};
const key=fn=>fn.schema_name+"."+fn.name+"("+fn.args+")";
function parseFields(result){
  const match=/^TABLE\s*\((.*)\)$/is.exec(result||"");
  ensure(match,"unsupported result shape; manual review required");
  const entries=match[1].split(",").map(part=>{
    const m=/^\s*([a-z_][\w]*)\s+(.+?)\s*$/i.exec(part);
    ensure(m,"unrecognized RETURNS TABLE field");
    return [m[1].toLowerCase(),m[2].trim().toLowerCase()];
  });
  ensure(new Set(entries.map(([n])=>n)).size===entries.length,"duplicate output field");
  return Object.fromEntries(entries);
}
export function compareRpcCatalogContracts(before,after,identities){
  ensure(Array.isArray(identities)&&identities.length,"protected identities required");
  ensure(new Set(identities).size===identities.length,"duplicate protected identities");
  for(const x of [before,after])ensure(Array.isArray(x?.functions),"catalog-shaped snapshot required");
  const old=new Map(before.functions.map(fn=>[key(fn),fn]));
  const next=new Map(after.functions.map(fn=>[key(fn),fn]));
  const changes=[];
  for(const id of identities){
    ensure(typeof id==="string"&&/^\w+\.\w+\([^()]*\)$/.test(id),"invalid RPC identity "+id);
    const l=old.get(id),r=next.get(id);
    if(!l||!r){changes.push({id,status:"review-required",reason:!l?"missing-before":"missing-after"});continue}
    let lf,rf;
    try{lf=parseFields(l.result);rf=parseFields(r.result)}
    catch{changes.push({id,status:"review-required",reason:"unsupported-output"});continue}
    const incompatible=Object.entries(lf).filter(([n,t])=>rf[n]!==t).map(([n])=>n);
    const securityChanged=l.security_definer!==r.security_definer||JSON.stringify(l.settings??null)!==JSON.stringify(r.settings??null);
    const definitionChanged=l.definition!==r.definition;
    const outputChanged=JSON.stringify(lf)!==JSON.stringify(rf);
    changes.push({id,status:incompatible.length||securityChanged||definitionChanged?"review-required":"signature-compatible",
      reason:incompatible.length?"removed-or-retyped-fields":securityChanged?"security-changed":definitionChanged?"implementation-changed":outputChanged?"additive-fields":"unchanged",
      incompatibleFields:incompatible});
  }
  return {changes,requiresReview:changes.some(x=>x.status==="review-required"),releaseApproved:false,dependencyGraphComplete:false,
    warnings:["Signature comparison cannot prove SQL dependencies, data semantics, or snapshot provenance."]};
}
