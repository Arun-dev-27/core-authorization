import { join } from 'node:path';
import type { DataSourceOptions } from 'typeorm';
import type { Env } from '@config/configuration';
import { ADMIN_DB_ENTITIES, useAdminSchema } from './entities';

export function buildDataSourceOptions(env: Env): DataSourceOptions {
  useAdminSchema(env.AUTHZ_DB_SCHEMA);
  return {
    type: 'postgres',
    host: env.AUTHZ_DB_HOST,
    port: env.AUTHZ_DB_PORT,
    username: env.AUTHZ_DB_USER,
    password: env.AUTHZ_DB_PASSWORD,
    database: env.AUTHZ_DB_NAME,
    ssl: env.AUTHZ_DB_SSL ? { rejectUnauthorized: true } : false,
    // Never let TypeORM create, alter or drop anything: the entities only map the existing admin_db tables.
    synchronize: false,
    migrationsRun: false,
    dropSchema: false,
    logging: false,
    entities: ADMIN_DB_ENTITIES,
    // An externally owned database (admin_db, Alembic-managed) must never receive this service's migrations.
    migrations: env.AUTHZ_DB_MIGRATIONS_ENABLED ? [join(__dirname, 'migrations', '*.{ts,js}')] : [],
    migrationsTableName: 'schema_migrations',
    extra: { max: 20, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 5_000 },
  };
}
