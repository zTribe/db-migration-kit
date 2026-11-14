export declare function verifyMigrationContracts(configPath: string, contracts: Array<{ version: string; required?: RegExp[]; forbidden?: RegExp[] }>): Promise<Array<{ version: string; checked: number }>>;
export declare function assertLocalTestDatabase(databaseUrl: string): URL;
