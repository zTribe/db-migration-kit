import { OBJECT_KINDS, TABLE_PERMISSIONS, COLUMN_PERMISSIONS, SEQUENCE_PERMISSIONS } from "./object-model.js";

const PRIVILEGES = {
  schema: ["USAGE","CREATE"],
  table: TABLE_PERMISSIONS,
  column: COLUMN_PERMISSIONS,
  function: ["EXECUTE"],
  sequence: SEQUENCE_PERMISSIONS,
};

const FORBIDDEN = new Set(["__proto__","constructor","prototype"]);
function own(object,key) {return Object.prototype.hasOwnProperty.call(object ?? {},key);}

/**
 * Canonical object-level policy. These are APPROVED desired privileges, not
 * instructions to grant or revoke permissions. Absent entries are unasserted.
 *
 * { objectPolicies: [
 *   { kind:"column", key:"app.rooms.message_seq",
 *     privileges:{anon:{UPDATE:"deny"},chat_owner:{UPDATE:"allow"}} }
 * ] }
 */
export function evaluateObjectPolicies(snapshot, rules = {}) {
  const facts = snapshot.inventory?.objects ?? [];
  const byObject = new Map(facts.map(x=>[`${x.kind}:${x.key}`,x]));
  const violations=[];
  const fail=(code,object,role,permission,expected,actual,reason) =>
    violations.push({code,objectKind:object.kind,objectKey:object.key,
      role:role ?? null,permission:permission ?? null,expected,actual,reason,
      message:`${object.kind} ${object.key}: ${role ? role+" " : ""}${permission ? permission+" " : ""}${reason}`});
  const seen=new Set();
  for(const item of rules.objectPolicies ?? []) {
    if (!item || !OBJECT_KINDS.includes(item.kind) || typeof item.key!=="string" || !item.key)
      throw new Error("invalid objectPolicies entry: kind/key required");
    const id=`${item.kind}:${item.key}`;
    if(seen.has(id)) throw new Error(`duplicate object policy ${id}`);
    seen.add(id);
    const target={kind:item.kind,key:item.key};
    const fact=byObject.get(id);
    if(!fact) {fail("OBJECT_MISSING",target,null,null,"present","missing","required object is missing");continue;}
    for (const [property,value] of Object.entries(item)) {
      if (["kind","key","privileges","source","reviewStatus"].includes(property))continue;
      if (property==="memberOf" || property==="denyMemberOf") {
        if(item.kind!=="role" || !Array.isArray(value)) throw new Error(`${id}: ${property} requires role array`);
        for(const parent of value) {
          const exists=(snapshot.memberships ?? []).some(x=>x.member===item.key && x.parent===parent);
          if(property==="memberOf"&&!exists)fail("ROLE_MEMBERSHIP_MISMATCH",target,item.key,parent,true,false,"required membership is missing");
          if(property==="denyMemberOf"&&exists)fail("ROLE_MEMBERSHIP_MISMATCH",target,item.key,parent,false,true,"forbidden membership exists");
        }
      } else {
        if(!["owner","rls","forceRls","securityDefiner","searchPath","superuser","bypassRls","command","permissive","roles","using","check"].includes(property))
          throw new Error(`${id}: unsupported object policy property ${property}`);
        if (["roles"].includes(property)) {
          const actual=[...(fact.roles ?? [])].sort(), expected=[...value].sort();
          if(JSON.stringify(actual)!==JSON.stringify(expected))fail("OBJECT_PROPERTY_MISMATCH",target,null,property,expected,actual,`expected ${property} differs`);
        } else if(fact[property]!==value)fail("OBJECT_PROPERTY_MISMATCH",target,null,property,value,fact[property]??null,`expected ${property} differs`);
      }
    }
    for(const [role,assertions] of Object.entries(item.privileges ?? {})) {
      if(FORBIDDEN.has(role))throw new Error("reserved role key not allowed");
      if(!snapshot.roles.some(x=>x.rolname===role)) {
        fail("ROLE_MISSING",target,role,null,"present","missing","required role is missing");
        continue;
      }
      const available=PRIVILEGES[item.kind];
      if(!available) throw new Error(`${id}: privileges unsupported for object kind ${item.kind}`);
      const grants=snapshot.privileges?.[item.kind+"s"]?.[role]?.[item.key];
      if(!grants) {
        fail("PRIVILEGE_FACT_MISSING",target,role,null,"collected","missing","effective privileges were not collected");
        continue;
      }
      for(const [permission,decision] of Object.entries(assertions)) {
        if(!available.includes(permission) || !["allow","deny"].includes(decision))
          throw new Error(`${id}: invalid ${permission} privilege decision`);
        const actual=grants[permission];
        if(typeof actual!=="boolean") {
          fail("PRIVILEGE_FACT_MISSING",target,role,permission,decision,actual??null,"effective privilege not collected");
        } else if(actual!==(decision==="allow")) {
          fail("PRIVILEGE_MISMATCH",target,role,permission,decision,actual,
            decision==="deny"?"has forbidden effective privilege":"lacks required effective privilege");
        }
      }
    }
  }
  return violations;
}
