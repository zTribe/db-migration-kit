import {compareSchemaCatalog,readSchemaCatalogOnClient} from "./schema-audit.js";
import {qualifiedName} from "./identifiers.js";

const SECTIONS=["tables","columns","constraints","indexes","triggers","functions","policies","publications"];
/** Exclude ONLY the kit-owned ledger created immediately before baseline validation. */
export function omitMigrationLedger(snapshot,schema,ledgerTable){
  const result=structuredClone(snapshot);
  for(const section of SECTIONS) result[section]=result[section].filter(item=>{
    if(section==="tables")return !(item.schema_name===schema&&item.name===ledgerTable);
    return !(item.schema_name===schema&&item.table_name===ledgerTable);
  });
  return result;
}
/**
 * Called from applyMigrations, while its advisory lock is held.
 * Existing untracked databases are eligible only with an exact versioned,
 * independently approved catalog proof. Never guess from table existence.
 */
export async function autoBaselineVerifiedCatalog(client, config, migrations){
  const options=config.autoBaseline;
  if(!options)return [];
  if(!options.expectedCatalog||typeof options.through!=="string"||!Array.isArray(options.schemas))
    throw new Error("autoBaseline requires expectedCatalog, schemas and through");
  const q=qualifiedName(config.schema,config.ledgerTable);
  const current=await client.query(`SELECT version FROM ${q} LIMIT 1`);
  if(current.rowCount)return [];
  const last=migrations.findIndex(m=>m.version===options.through);
  if(last<0)throw new Error("autoBaseline through version is absent from manifest");
  const live=omitMigrationLedger(await readSchemaCatalogOnClient(client,options.schemas),config.schema,config.ledgerTable);
  const match=compareSchemaCatalog(options.expectedCatalog,live);
  if(!match.ok) {
    // A newly provisioned empty DB must execute all migrations rather than baseline.
    if(!live.tables.length && !live.functions.length && !live.sequences.length &&
      !live.publications.length)return [];
    const problem=match.differences.slice(0,5).map(x=>`${x.section}:${x.key} ${x.code}`).join("; ");
    throw new Error(`automatic baseline refused: live schema differs from approved catalog: ${problem}`);
  }
  const recorded=[];
  await client.query("BEGIN");
  try{
    for(const migration of migrations.slice(0,last+1)){
      await client.query(
        `INSERT INTO ${q} (version,name,checksum,source) VALUES ($1,$2,$3,'baseline')`,
        [migration.version,migration.name,migration.checksum],
      );
      recorded.push(migration.version);
    }
    await client.query("COMMIT");
  }catch(error){await client.query("ROLLBACK").catch(()=>{});throw error}
  return recorded;
}

/**
 * Fail before ledger/schema DDL if an existing untracked database doesn't
 * match its independently approved snapshot.
 */
export async function preflightAutoBaselineCatalog(client,config) {
  const options=config.autoBaseline;
  if(!options)return {eligible:false};
  if(!options.expectedCatalog || !Array.isArray(options.schemas) || !options.schemas.length)
    throw new Error("autoBaseline expectedCatalog and schemas required");
  const q=qualifiedName(config.schema,config.ledgerTable);
  const exists=(await client.query("SELECT pg_catalog.to_regclass($1) IS NOT NULL AS present",[q])).rows[0].present;
  if(exists){
    const count=await client.query(`SELECT count(*)::int AS n FROM ${q}`);
    if(count.rows[0].n) return {eligible:false};
  }
  const live=omitMigrationLedger(await readSchemaCatalogOnClient(client,options.schemas),config.schema,config.ledgerTable);
  const match=compareSchemaCatalog(options.expectedCatalog,live);
  if(match.ok) return {eligible:true};
  if(!live.tables.length&&!live.functions.length&&!live.sequences.length&&!live.publications.length)
    return {eligible:false,fresh:true};
  throw new Error(`automatic baseline refused before writes: live schema differs from approved catalog; ${match.differences.slice(0,5).map(x=>x.section+":"+x.key+" "+x.code).join("; ")}`);
}
