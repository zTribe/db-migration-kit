# Remote target identity contract

Remote migrations are **blocked** unless a live database marker matches a separately configured expected project reference and environment. This is designed to prevent accidental Dev/Production confusion when Supabase projects share the same pooler hostname.

## One-time database administration

Execute the following **only on a chosen non-production database**, with a privileged administrator, after independently verifying the target. Substitute your actual Dev project reference; do not commit credentials or the connection URL.

```sql
CREATE SCHEMA IF NOT EXISTS migration_control;
CREATE TABLE IF NOT EXISTS migration_control.target_identity (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  project_ref text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('dev', 'test', 'production'))
);
REVOKE ALL ON SCHEMA migration_control FROM PUBLIC;
REVOKE ALL ON TABLE migration_control.target_identity FROM PUBLIC;
INSERT INTO migration_control.target_identity(singleton,project_ref,environment)
VALUES (true,'<YOUR_DEV_PROJECT_REF>','dev');
-- Replace the placeholder below with the *dedicated migration login role*:
-- GRANT USAGE ON SCHEMA migration_control TO your_migration_login;
-- GRANT SELECT ON TABLE migration_control.target_identity TO your_migration_login;
-- Do not grant INSERT/UPDATE/DELETE or ownership of this marker to migration/runtime roles.
```

The identity marker **must be provisioned independently from the migration runner**, and owned by a separate administrator. If the migration login is a database superuser or can change the marker, the marker does not provide an independent trust boundary; use a least-privilege migration login and additional operational approvals.

## Non-secret adapter configuration

```json
{
  "targetIdentity": {
    "schema": "migration_control",
    "table": "target_identity",
    "projectRef": "your-dev-project-reference",
    "environment": "dev"
  }
}
```

For remote apply, CLI additionally requires `apply --yes --allow-remote`. This is not authorization to modify Production: the CLI rejects any expected environment other than `dev`. The live marker must match. Neither the remote URL hostname nor `--allow-remote` alone establishes database identity.

**No automatic production marker setup or production database writes are part of this library's CI.** Isolated PG17 tests create and delete only their own temporary schemas and roles.
