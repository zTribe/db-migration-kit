/**
 * Canonical, versioned object inventory shared by Indexer and Chat.
 * Object keys are stable, fully qualified identifiers. Function keys include
 * PostgreSQL identity arguments; column keys use schema.table.column.
 * This is a data model, not a granted/approved security policy.
 */
export const OBJECT_MODEL_VERSION = 1;
export const OBJECT_KINDS = Object.freeze(["schema","table","column","function","role","sequence","policy"]);
export const TABLE_PERMISSIONS = Object.freeze(["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER"]);
export const COLUMN_PERMISSIONS = Object.freeze(["SELECT","INSERT","UPDATE","REFERENCES"]);
export const SEQUENCE_PERMISSIONS = Object.freeze(["USAGE","SELECT","UPDATE"]);

export function inventorySecurityObjects(snapshot) {
  const entities = [];
  const add = (kind,key,attributes) => entities.push({kind,key,...attributes});
  for (const schema of snapshot.schemaObjects ?? (snapshot.schemas ?? []).map(name=>({schema_name:name}))) {
    add("schema",schema.schema_name,{owner:schema.owner_name ?? null});
  }
  for (const table of snapshot.tables ?? []) {
    add("table",`${table.schema_name}.${table.relname}`,{
      owner:table.owner_name,rls:table.relrowsecurity,forceRls:table.relforcerowsecurity,
    });
  }
  for (const col of snapshot.columns ?? []) {
    add("column",`${col.schema_name}.${col.table_name}.${col.column_name}`,{
      owner:col.owner_name ?? null,
    });
  }
  for (const fn of snapshot.functions ?? []) {
    add("function",`${fn.schema_name}.${fn.proname}(${fn.identity_args})`,{
      owner:fn.owner_name,securityDefiner:fn.security_definer,
      searchPath:(fn.proconfig ?? []).find(item=>item.startsWith("search_path="))?.slice(12) ?? null,
    });
  }
  for (const role of snapshot.roles ?? []) {
    add("role",role.rolname,{superuser:role.rolsuper,bypassRls:role.rolbypassrls});
  }
  for (const seq of snapshot.sequences ?? []) {
    add("sequence",`${seq.schema_name}.${seq.relname}`,{owner:seq.owner_name});
  }
  for (const policy of snapshot.policies ?? []) {
    add("policy",`${policy.schema_name}.${policy.table_name}.${policy.policy_name}`,{
      command:policy.command,permissive:policy.permissive,roles:policy.roles,
      using:policy.using_expr ?? null,check:policy.check_expr ?? null,
    });
  }
  const seen=new Set();
  for (const object of entities) {
    if (!OBJECT_KINDS.includes(object.kind)) throw new Error(`unknown security object kind: ${object.kind}`);
    const id=`${object.kind}:${object.key}`;
    if (seen.has(id)) throw new Error(`duplicate security inventory object: ${id}`);
    seen.add(id);
  }
  entities.sort((a,b)=>a.kind.localeCompare(b.kind)||a.key.localeCompare(b.key));
  return {version:OBJECT_MODEL_VERSION,objects:entities};
}
