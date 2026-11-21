#!/usr/bin/env node
/** Compare two local SQL Editor JSON/CSV exports without connecting to a database. */
import {readFileSync} from "node:fs";
import {parseLiveEnvironmentSnapshot,compareLiveEnvironmentSnapshots} from "../src/live-environment-snapshot.js";
const [dev,prod,...options]=process.argv.slice(2);
if(!dev||!prod||options.some(x=>x!=="--strict")){
  console.error("Usage: node bin/compare-live-snapshots.js <dev.csv|json> <production.csv|json> [--strict]");
  process.exit(2);
}
try{
  const report=compareLiveEnvironmentSnapshots(
    parseLiveEnvironmentSnapshot(readFileSync(dev,"utf8")),
    parseLiveEnvironmentSnapshot(readFileSync(prod,"utf8")));
  console.log(JSON.stringify(report,null,2));
  if(report.status==="block"||(options.includes("--strict")&&report.status!=="aligned"))
    process.exitCode=1;
}catch(error){
  console.error("Snapshot comparison failed: "+error.message);
  process.exitCode=2;
}
