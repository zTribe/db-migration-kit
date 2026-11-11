export function quoteIdentifier(value) {
  if (typeof value !== "string" || !/^[a-z_][a-z0-9_]*$/i.test(value)) {
    throw new Error(`unsafe PostgreSQL identifier: ${String(value)}`);
  }
  return '"' + value.replaceAll('"', '""') + '"';
}

export function qualifiedName(schema, table) {
  return `${quoteIdentifier(schema)}.${quoteIdentifier(table)}`;
}
