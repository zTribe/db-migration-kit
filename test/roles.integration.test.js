import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes } from "node:crypto";

const url=process.env.PG_TEST_URL;
test("real PG17: role membership and function ownership errors reproduce Indexer deployment failures", {skip:!url}, async()=>{
  const pool=new pg.Pool({connectionString:url,max:2});
  const client=await pool.connect();
  const schema="kit_role_boundary_it";
  const parsed = new URL(url);
  const password = randomBytes(20).toString("hex");
  let deployer;
  try{
    await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await client.query("DROP ROLE IF EXISTS kit_role_deployer_it");
    await client.query("DROP ROLE IF EXISTS kit_role_owner_it");
    await client.query(`CREATE ROLE kit_role_deployer_it LOGIN PASSWORD '${password}' NOSUPERUSER NOBYPASSRLS`);
    await client.query("CREATE ROLE kit_role_owner_it NOLOGIN NOSUPERUSER NOBYPASSRLS");
    await client.query(`CREATE SCHEMA ${schema}`);
    await client.query(`CREATE FUNCTION ${schema}.example() RETURNS integer LANGUAGE sql AS 'SELECT 1'`);
    await client.query(`GRANT USAGE ON SCHEMA ${schema} TO kit_role_deployer_it`);
    deployer = new pg.Client({
      host: parsed.hostname,
      port: Number(parsed.port || 5432),
      database: parsed.pathname.slice(1) || "postgres",
      user: "kit_role_deployer_it",
      password,
    });
    await deployer.connect();
    await assert.rejects(
      () => deployer.query("SET ROLE kit_role_owner_it"),
      e=> e.code==="42501" && /permission denied to set role/.test(e.message),
      "non-superuser must not be able to SET ROLE an unrelated owner",
    );
    await assert.rejects(
      () => deployer.query(`ALTER FUNCTION ${schema}.example() OWNER TO kit_role_owner_it`),
      e=> e.code==="42501" && /must be owner of function/.test(e.message),
      "real migration login must not alter a function it does not own",
    );
    await client.query("GRANT kit_role_owner_it TO kit_role_deployer_it");
    await deployer.query("SET ROLE kit_role_owner_it");
    const current=await deployer.query("SELECT current_user AS role_name");
    assert.equal(current.rows[0].role_name,"kit_role_owner_it");
    await deployer.query("RESET ROLE");
  }finally{
    if (deployer) await deployer.end().catch(()=>undefined);
    await client.query("RESET ROLE").catch(()=>undefined);
    await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(()=>undefined);
    await client.query("REVOKE kit_role_owner_it FROM kit_role_deployer_it").catch(()=>undefined);
    await client.query("DROP ROLE IF EXISTS kit_role_deployer_it").catch(()=>undefined);
    await client.query("DROP ROLE IF EXISTS kit_role_owner_it").catch(()=>undefined);
    client.release();
    await pool.end();
  }
});
