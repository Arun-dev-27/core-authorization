// Integration tests run against miqaat_authz_test and Redis DB index 1 (see .env.test).
process.env.NODE_ENV = 'test';
process.env.ENV_FILE = process.env.ENV_FILE ?? '.env.test';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { loadEnvFiles } = require('@config/configuration') as typeof import('@config/configuration');
loadEnvFiles();

// These suites run migrations and TRUNCATE / DELETE tables. They must only ever touch a throwaway database of
// this service's own, never the existing admin_db - which is exactly what AUTHZ_DB_MIGRATIONS_ENABLED=false marks.
if (process.env.AUTHZ_DB_MIGRATIONS_ENABLED !== 'true') {
  throw new Error('e2e tests reset tables: refusing to run unless AUTHZ_DB_MIGRATIONS_ENABLED=true (a throwaway test database, never admin_db)');
}
