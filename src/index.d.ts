export type MigrationEntry = string | { file: string; version: string };
export type MigrationConfig = { directory: string; files: MigrationEntry[]; schema?: string; ledgerTable?: string; lockName?: string; beforeMigrations?: (client: any, config: any) => Promise<void>; beforeMigration?: (client: any, migration: {version:string;name:string;file:string;sql:string;checksum:string}, config: any) => Promise<void> };
export function checksumText(sql: string): string;
export function loadManifest(config: MigrationConfig): Promise<Array<{version:string;name:string;file:string;sql:string;checksum:string}>>;
export function inspectMigrations(pool: any, config: MigrationConfig): Promise<any>;
export function applyMigrations(pool: any, config: MigrationConfig): Promise<{applied:string[];total:number}>;
export function auditMigrations(pool: any, config: MigrationConfig): Promise<any>;
export function inspectRuntimeSecurity(pool: any, rules: any): Promise<{ok:boolean;failures:string[];snapshot:any}>;
export const SECURITY_CATALOG_SQL: string;
