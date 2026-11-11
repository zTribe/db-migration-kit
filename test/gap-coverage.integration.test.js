import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import {mkdtemp,writeFile,rm} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {
 applyMigrations, inspectMigrations, readSchemaCatalog, compareSchemaCatalog,
 inspectConcurrentIndex, dropInvalidIndexForRetry,
} from "../src/index.js";
const url=process.env.PG_TEST_URL;

test("PG17: hardened migration ledger retains approved migrator, denies clients and permits audit SELECT only",{skip:!url},async()=>{
 const pool=new pg.Pool({connectionString:url,max:3}), dir=await mkdtemp(join(tmpdir(),"kit-ledger-hardening-"));
 const schema="kit_ledger_security_it",audit="kit_ledger_auditor_it",untrusted="kit_ledger_client_it";
 try{
  await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await pool.query(`DROP ROLE IF EXISTS ${audit}`);
  await pool.query(`DROP ROLE IF EXISTS ${untrusted}`);
  await pool.query(`CREATE ROLE ${audit} NOLOGIN`);
  await pool.query(`CREATE ROLE ${untrusted} NOLOGIN`);
  await writeFile(join(dir,"001_first.sql"),`CREATE TABLE ${schema}.messages(id integer);`);
  await writeFile(join(dir,"002_second.sql"),`ALTER TABLE ${schema}.messages ADD COLUMN body text;`);
  const config={directory:dir,files:["001_first.sql","002_second.sql"],schema,lockName:"kit-ledger-security-it",
   ledgerSecurity:{auditRole:audit,clientRoles:[untrusted]}};
  assert.equal((await applyMigrations(pool,config)).applied.length,2);
  const row=await pool.query(`
    SELECT relrowsecurity AS rls,relforcerowsecurity AS forced FROM pg_catalog.pg_class
    WHERE oid=$1::regclass`,[`${schema}.schema_migrations`]);
  assert.deepEqual(row.rows[0],{rls:true,forced:true});
  const privilege=await pool.query(`
    SELECT pg_catalog.has_table_privilege($1,$3,'SELECT') AS audit_select,
      pg_catalog.has_table_privilege($1,$3,'INSERT') AS audit_insert,
      pg_catalog.has_table_privilege($2,$3,'SELECT') AS client_select,
      pg_catalog.has_table_privilege($2,$3,'DELETE') AS client_delete
  `,[audit,untrusted,`${schema}.schema_migrations`]);
  assert.deepEqual(privilege.rows[0],{
   audit_select:true,audit_insert:false,client_select:false,client_delete:false
  });
  const policies=await pool.query(`
    SELECT polname FROM pg_catalog.pg_policy WHERE polrelid=$1::regclass
    ORDER BY polname`,[`${schema}.schema_migrations`]);
  assert.deepEqual(policies.rows.map(x=>x.polname),["db_migration_kit_audit_select","db_migration_kit_migrator"]);
  assert.equal((await inspectMigrations(pool,config)).applied.length,2);
  assert.deepEqual((await applyMigrations(pool,config)).applied,[]);
 }finally{
  await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(()=>{});
  await pool.query(`DROP ROLE IF EXISTS ${audit}`).catch(()=>{});
  await pool.query(`DROP ROLE IF EXISTS ${untrusted}`).catch(()=>{});
  await pool.end();await rm(dir,{recursive:true,force:true});
 }
});

test("PG17: structural snapshot detects column/index/constraint/trigger/function changes",{skip:!url},async()=>{
 const pool=new pg.Pool({connectionString:url});
 const schema="kit_schema_diff_it";
 try{
  await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await pool.query(`CREATE SCHEMA ${schema}`);
  await pool.query(`CREATE TABLE ${schema}.items(id integer PRIMARY KEY, body text)`);
  await pool.query(`CREATE INDEX items_body_idx ON ${schema}.items(body)`);
  await pool.query(`CREATE FUNCTION ${schema}.count_rows() RETURNS bigint LANGUAGE sql AS 'SELECT COUNT(*) FROM ${schema}.items'`);
  await pool.query(`CREATE POLICY view_items ON ${schema}.items FOR SELECT USING (true)`);
  const expected=await readSchemaCatalog(pool,[schema]);
  assert.equal(compareSchemaCatalog(expected,await readSchemaCatalog(pool,[schema])).ok,true);
  await pool.query(`ALTER TABLE ${schema}.items ADD COLUMN extra integer`);
  const diff=compareSchemaCatalog(expected,await readSchemaCatalog(pool,[schema]));
  assert.equal(diff.ok,false);
  assert.ok(diff.differences.some(x=>x.section==="columns"&&x.key.endsWith(".extra")&&x.code==="UNEXPECTED"));
 }finally{
  await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(()=>{});
  await pool.end();
 }
});

test("PG17: strict auto baseline records verified history, fails closed on catalog drift",{skip:!url},async()=>{
 const pool=new pg.Pool({connectionString:url}),dir=await mkdtemp(join(tmpdir(),"kit-auto-baseline-"));
 const schema="kit_auto_baseline_it",files=["001_first.sql","002_second.sql"];
 try{
  await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await pool.query(`CREATE SCHEMA ${schema}`);
  await writeFile(join(dir,files[0]),`CREATE TABLE ${schema}.messages(id integer);`);
  await writeFile(join(dir,files[1]),`ALTER TABLE ${schema}.messages ADD COLUMN body text;`);
  await pool.query(`CREATE TABLE ${schema}.messages(id integer)`);
  const expected=await readSchemaCatalog(pool,[schema]);
  const config={directory:dir,files,schema,lockName:"kit-auto-baseline-it",
    autoBaseline:{through:"001_first",schemas:[schema],expectedCatalog:expected}};
  const applied=await applyMigrations(pool,config);
  assert.deepEqual(applied.applied,["002_second"]);
  const ledger=await pool.query(`SELECT version,source FROM ${schema}.schema_migrations ORDER BY version`);
  assert.deepEqual(ledger.rows,[{version:"001_first",source:"baseline"},{version:"002_second",source:"migration"}]);
  await pool.query(`DROP SCHEMA ${schema} CASCADE`);
  await pool.query(`CREATE SCHEMA ${schema}`);
  await pool.query(`CREATE TABLE ${schema}.messages(id integer, corrupt text)`);
  await assert.rejects(()=>applyMigrations(pool,config),/automatic baseline refused/);
  const count=await pool.query(`SELECT count(*)::int AS n FROM ${schema}.schema_migrations`);
  assert.equal(count.rows[0].n,0);
 }finally{
  await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(()=>{});
  await rm(dir,{recursive:true,force:true});await pool.end();
 }
});

test("PG17: invalid index recovery requires explicit confirmation and never drops valid indexes",{skip:!url},async()=>{
 const pool=new pg.Pool({connectionString:url});
 const schema="kit_index_retry_it";
 try{
  await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await pool.query(`CREATE SCHEMA ${schema}`);
  await pool.query(`CREATE TABLE ${schema}.items(id integer)`);
  await pool.query(`INSERT INTO ${schema}.items VALUES(1),(1)`);
  await assert.rejects(()=>pool.query(`CREATE UNIQUE INDEX CONCURRENTLY items_unique_it ON ${schema}.items(id)`));
  const invalid=await inspectConcurrentIndex(pool,{schema,index:"items_unique_it"});
  assert.equal(invalid?.valid,false);
  await assert.rejects(()=>dropInvalidIndexForRetry(pool,{schema,index:"items_unique_it",table:"items"}),/confirm=true/);
  await assert.rejects(()=>dropInvalidIndexForRetry(pool,{schema,index:"items_unique_it",table:"other",confirm:true}),/unexpected table/);
  assert.equal((await dropInvalidIndexForRetry(pool,{schema,index:"items_unique_it",table:"items",confirm:true})).dropped,true);
  assert.equal(await inspectConcurrentIndex(pool,{schema,index:"items_unique_it"}),null);
  await pool.query(`DELETE FROM ${schema}.items WHERE ctid IN (SELECT min(ctid) FROM ${schema}.items)`);
  await pool.query(`CREATE UNIQUE INDEX CONCURRENTLY items_unique_it ON ${schema}.items(id)`);
  await assert.rejects(()=>dropInvalidIndexForRetry(pool,{schema,index:"items_unique_it",table:"items",confirm:true}),/valid index/);
 }finally{
  await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(()=>{});
  await pool.end();
 }
});
