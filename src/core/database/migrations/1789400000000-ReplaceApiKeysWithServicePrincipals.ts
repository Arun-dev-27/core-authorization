import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Removes shared-secret API keys. Calling services are now registered service principals that
 * authenticate with short-lived RS256 JWTs verified against their own published JWKS
 * (private key never leaves the caller; nothing secret is stored here).
 */
export class ReplaceApiKeysWithServicePrincipals1789400000000 implements MigrationInterface {
  name = 'ReplaceApiKeysWithServicePrincipals1789400000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE service_principals (
        id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        principal_id       varchar(64)   NOT NULL UNIQUE CHECK (principal_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
        name               varchar(200)  NOT NULL,
        jwks_uri           varchar(2048) NOT NULL CHECK (jwks_uri !~ '\\*'),
        scopes             text[]        NOT NULL,
        allowed_client_ids text[],
        status             varchar(16)   NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
        last_used_at       timestamptz,
        created_at         timestamptz   NOT NULL DEFAULT now(),
        updated_at         timestamptz   NOT NULL DEFAULT now(),
        revoked_at         timestamptz
      )`);
    await q.query(`DROP TABLE IF EXISTS api_clients`);
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE api_clients (
        id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        name               varchar(128) NOT NULL UNIQUE,
        key_prefix         varchar(32)  NOT NULL UNIQUE,
        key_hash           char(64)     NOT NULL,
        scopes             text[]       NOT NULL,
        allowed_client_ids text[],
        status             varchar(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
        last_used_at       timestamptz,
        created_at         timestamptz  NOT NULL DEFAULT now(),
        revoked_at         timestamptz
      )`);
    await q.query(`DROP TABLE IF EXISTS service_principals`);
  }
}
