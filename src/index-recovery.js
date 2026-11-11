import {qualifiedName} from "./identifiers.js";

/** Introspection only; never modifies an index. */
export async function inspectConcurrentIndex(client,{schema,index}){
  if(!schema||!index)throw new Error("schema and index are required");
  const {rows}=await client.query(`
    SELECT n.nspname AS schema_name,i.relname AS index_name,
           c.relname AS table_name,x.indisvalid AS valid,x.indisready AS ready,
           pg_catalog.pg_get_indexdef(i.oid) AS definition
    FROM pg_catalog.pg_class i
    JOIN pg_catalog.pg_namespace n ON n.oid=i.relnamespace
    JOIN pg_catalog.pg_index x ON x.indexrelid=i.oid
    JOIN pg_catalog.pg_class c ON c.oid=x.indrelid
    WHERE n.nspname=$1 AND i.relname=$2
  `,[schema,index]);
  return rows[0] ?? null;
}
/**
 * Recovery is NEVER automatic. Caller supplies the exact expected schema,
 * index and containing table; only an already-invalid index may be dropped.
 * Must be run outside a transaction and under a caller-held migration lock.
 * After recovery, normal migration re-executes its CREATE INDEX CONCURRENTLY.
 */
export async function dropInvalidIndexForRetry(client,{schema,index,table,confirm=false}){
  if(confirm!==true)throw new Error("invalid index recovery requires explicit confirm=true");
  if(!table)throw new Error("expected table is required");
  const found=await inspectConcurrentIndex(client,{schema,index});
  if(!found)return {dropped:false,reason:"not_found"};
  if(found.table_name!==table)throw new Error("invalid index belongs to an unexpected table");
  if(found.valid)throw new Error("refusing to drop a valid index");
  await client.query(`DROP INDEX CONCURRENTLY ${qualifiedName(schema,index)}`);
  return {dropped:true,index:`${schema}.${index}`};
}
