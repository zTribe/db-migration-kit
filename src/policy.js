/** Pure, database-free policy evaluator. No SQL execution or network dependencies. */
export function evaluateSecurityPolicy(snapshot, rules = {}) {
  const failures = [];
  const tables = new Map(snapshot.tables.map(t => [`${t.schema_name}.${t.relname}`,t]));
  const functions = new Map(snapshot.functions.map(f => [`${f.schema_name}.${f.proname}(${f.identity_args})`,f]));
  const roles = new Map(snapshot.roles.map(r => [r.rolname,r]));
  const schemas = rules.schemas ?? ["app"];
  const requiredRls = new Set(rules.requireRlsOn ?? []);
  const forceRls = new Set(rules.requireForceRlsOn ?? []);
  const requiredTables = new Set([...(rules.requiredTables ?? []),...requiredRls,...forceRls]);
  for (const name of requiredTables) if (!tables.has(name)) failures.push(`${name}: required table is missing`);
  for (const name of rules.requiredFunctions ?? []) if (!functions.has(name)) failures.push(`${name}: required function is missing`);
  for (const [name,owner] of Object.entries(rules.expectedTableOwners ?? {})) {
    const t=tables.get(name);
    if (!t) failures.push(`${name}: expected owner ${owner}, but table is missing`);
    else if (t.owner_name!==owner) failures.push(`${name}: expected owner ${owner}; actual ${t.owner_name}`);
  }
  for (const [name,owner] of Object.entries(rules.expectedFunctionOwners ?? {})) {
    const f=functions.get(name);
    if (!f) failures.push(`${name}: expected owner ${owner}, but function is missing`);
    else if (f.owner_name!==owner) failures.push(`${name}: expected owner ${owner}; actual ${f.owner_name}`);
  }
  const configuredRoles = new Set([
    ...(rules.requiredRoles ?? []),...(rules.forbidBypassRlsRoles ?? []),
    ...(rules.forbidSuperuserRoles ?? []),...(rules.deniedExecuteRoles ?? []),
    ...(rules.deniedTableDmlRoles ?? []),...(rules.deniedTableSelectRoles ?? []),
    ...(rules.deniedSchemaUsageRoles ?? []),...(rules.deniedSchemaCreateRoles ?? []),
    ...Object.keys(rules.allowedTablePrivileges ?? {}),
    ...Object.keys(rules.allowedSchemaPrivileges ?? {}),
  ]);
  for (const role of configuredRoles) if (!roles.has(role)) failures.push(`${role}: required role is missing`);
  for (const name of rules.forbidBypassRlsRoles ?? []) if (roles.get(name)?.rolbypassrls) failures.push(`${name}: role has BYPASSRLS`);
  for (const name of rules.forbidSuperuserRoles ?? []) if (roles.get(name)?.rolsuper) failures.push(`${name}: role has SUPERUSER`);
  for (const [name,t] of tables) {
    if (requiredRls.has(name) && !t.relrowsecurity) failures.push(`${name}: RLS is disabled`);
    if (forceRls.has(name) && !t.relforcerowsecurity) failures.push(`${name}: FORCE RLS is disabled`);
  }
  const allowedOwners = new Set(rules.allowedDefinerOwners ?? []);
  for (const name of Object.keys(rules.expectedDefinerSearchPaths ?? {})) if (!functions.has(name)) failures.push(`${name}: expected SECURITY DEFINER function is missing`);
  for (const [name,fn] of functions) {
    if (!fn.security_definer) continue;
    if (!allowedOwners.has(fn.owner_name)) failures.push(`${name}: unexpected SECURITY DEFINER owner ${fn.owner_name}`);
    const searchPath=(fn.proconfig ?? []).find(setting => setting.startsWith("search_path="));
    const expectedPath=rules.expectedDefinerSearchPaths?.[name];
    if (expectedPath!==undefined && searchPath!==`search_path=${expectedPath}`) failures.push(`${name}: expected exact search_path ${expectedPath}; actual ${searchPath ?? "unset"}`);
    if (rules.requireFixedSearchPath!==false && !searchPath) failures.push(`${name}: SECURITY DEFINER has no fixed search_path`);
    if (searchPath && /(^|[, ])public([, ]|$)|\$user/i.test(searchPath)) failures.push(`${name}: unsafe search_path ${searchPath}`);
    if (fn.public_execute) failures.push(`${name}: PUBLIC can EXECUTE`);
    for (const role of rules.deniedExecuteRoles ?? [])
      if (snapshot.privileges.functions[role]?.[name]?.EXECUTE) failures.push(`${name}: ${role} can EXECUTE`);
  }
  for (const role of rules.deniedTableDmlRoles ?? []) for (const name of tables.keys()) {
    const effective = snapshot.privileges.tables[role]?.[name] ?? {};
    for (const p of ["INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER"])
      if (effective[p]) failures.push(`${role} has effective ${p} on ${name}`);
    if (rules.denySelectForDmlRoles && effective.SELECT) failures.push(`${role} has effective SELECT on ${name}`);
  }
  for (const role of rules.deniedTableSelectRoles ?? [])
    for (const name of tables.keys())
      if (snapshot.privileges.tables[role]?.[name]?.SELECT) failures.push(`${role} has effective SELECT on ${name}`);
  for (const role of rules.deniedSchemaUsageRoles ?? []) for (const schema of schemas)
    if (snapshot.privileges.schemas[role]?.[schema]?.USAGE) failures.push(`${role} has USAGE on schema ${schema}`);
  for (const role of rules.deniedSchemaCreateRoles ?? []) for (const schema of schemas)
    if (snapshot.privileges.schemas[role]?.[schema]?.CREATE) failures.push(`${role} has CREATE on schema ${schema}`);
  for (const [role,desired] of Object.entries(rules.allowedSchemaPrivileges ?? {}))
    for (const schema of schemas) for (const privilege of desired)
      if (!snapshot.privileges.schemas[role]?.[schema]?.[privilege]) failures.push(`${role} lacks ${privilege} on schema ${schema}`);
  for (const [role,desired] of Object.entries(rules.allowedTablePrivileges ?? {}))
    for (const name of tables.keys()) for (const privilege of desired)
      if (!snapshot.privileges.tables[role]?.[name]?.[privilege]) failures.push(`${role} lacks ${privilege} on ${name}`);
  return failures;
}
