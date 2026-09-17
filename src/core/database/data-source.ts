import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { loadEnv, loadEnvFiles } from '@config/configuration';
import { buildDataSourceOptions } from './data-source-options';

// Used by the TypeORM CLI (migrations) and the seed / onboarding scripts.
loadEnvFiles();
const env = loadEnv();

// Every consumer of this file either migrates (TypeORM creates its schema_migrations table even when there is
// nothing to run) or seeds rows. Neither may touch a database owned by another system, such as admin_db.
if (!env.AUTHZ_DB_MIGRATIONS_ENABLED) {
  throw new Error(
    `AUTHZ_DB_MIGRATIONS_ENABLED=false: ${env.AUTHZ_DB_NAME} is managed by another system; migrations and seed scripts must not run against it`,
  );
}

export default new DataSource(buildDataSourceOptions(env));
