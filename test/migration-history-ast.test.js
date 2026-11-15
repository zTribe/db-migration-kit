import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanMigrationHistoryAst } from "../src/migration-history-ast.js";
import { checksumText } from "../src/checksum.js";

test("historical AST scan keeps PG18 parser errors visible, never changes SQL",async()=>{
  const dir=await mkdtemp(join(tmpdir(),"kit-history-ast-"));
  try {
    const files=["001_one.sql","002_dynamic.sql","003_bad.sql"];
    const sql=[
      "ALTER TABLE app.messages ADD COLUMN note text;\n",
      "DO $$ BEGIN EXECUTE 'UPDATE app.messages SET note = ''a'''; END $$;\n",
      "ALTER TABLE app.messages ADD COLUMN;\n",
    ];
    await Promise.all(files.map((file,i)=>writeFile(join(dir,file),sql[i])));
    const report=await scanMigrationHistoryAst({directory:dir,files}, {changedFiles:["db/migrations/003_bad.sql"]});
    assert.deepEqual(report.summary,{files:3,parsed:1,reviewRequired:1,parseErrors:1,changed:1,changedParseErrors:1});
    assert.deepEqual(report.findings.map(x=>x.status),["parsed","review-required","parse-error"]);
    assert.equal(report.findings[0].checksum,checksumText(sql[0]));
    assert.equal(report.findings[2].changed,true);
    assert.ok(report.findings[2].parserError);
    assert.equal(report.releaseApproved,false);
  } finally { await rm(dir,{recursive:true,force:true}); }
});

test("historical AST scan refuses missing config and invalid paths",async()=>{
  await assert.rejects(()=>scanMigrationHistoryAst({directory:".",files:[]}),/validated/);
  await assert.rejects(()=>scanMigrationHistoryAst({directory:".",files:["../outside.sql"]}),/Invalid migration filename/);
});
