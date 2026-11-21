#!/usr/bin/env node
/** Generate a sanitized, source-controlled Production permission contract offline. */
import {readFileSync} from "node:fs";
import {parseLiveEnvironmentSnapshot} from "../src/live-environment-snapshot.js";
import {deriveProductionPermissionProfile} from "../src/production-permission-profile.js";
const [path,...args]=process.argv.slice(2);
const flag=k=>args.find(x=>x.startsWith("--"+k+"="))?.slice(k.length+3);
if(!path||!flag("project")||!flag("schemas")||!flag("roles"))
 throw Error("Usage: node bin/generate-production-profile.js prod.csv --project=chat|indexer --schemas=app --roles=postgres,...");
const snapshot=parseLiveEnvironmentSnapshot(readFileSync(path,"utf8"));
const profile=deriveProductionPermissionProfile(snapshot,{
 project:flag("project"),schemas:flag("schemas").split(","),roles:flag("roles").split(","),
 migrationRole:flag("migration-role")??"postgres"});
console.log(JSON.stringify(profile,null,2));
