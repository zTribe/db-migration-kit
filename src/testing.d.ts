export declare function verifyMigrationContracts(configPath: string, contracts: Array<{ version: string; required?: RegExp[]; forbidden?: RegExp[] }>): Promise<Array<{ version: string; checked: number }>>;
export declare function assertLocalTestDatabase(databaseUrl: string): URL;
export declare function withLocalPostgres<T>(databaseUrl: string, run: (pool: import("pg").Pool) => Promise<T>, options?: {max?:number}): Promise<T>;
