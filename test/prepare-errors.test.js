import test from "node:test";
import assert from "node:assert/strict";
import { explainPrepareFailure } from "../src/prepare-errors.js";
test("stable AI retry codes distinguish privilege and checksum failures",()=>{
 assert.equal(explainPrepareFailure(Error("permission denied to set role runtime_owner"),"capture").code,"OWNER_SET");
 assert.equal(explainPrepareFailure(Error("missing external ADMIN OPTION"),"capture").code,"OWNER_ADMIN");
 assert.equal(explainPrepareFailure(Error("owner is runtime_owner"),"capture").code,"OBJECT_CAPABILITY");
 assert.equal(explainPrepareFailure(Error("checksum mismatch"),"review").code,"MIGRATION_HISTORY");
 assert.equal(explainPrepareFailure(Error("targeted tests never ran --test-name-pattern"),"upgrade").code,"TEST_SELECTION");
 assert.equal(explainPrepareFailure(Error("docker daemon offline"),"environment").code,"LOCAL_PG17");
});
test("unknown failures remain fail-closed with the failed stage",()=>{
 const r=explainPrepareFailure(Error("unexpected failure"),"non-superuser-upgrade");
 assert.equal(r.code,"PREPARE_FAILED");assert.equal(r.stage,"non-superuser-upgrade");
 assert.equal(r.canPublishMigration,false);
});
