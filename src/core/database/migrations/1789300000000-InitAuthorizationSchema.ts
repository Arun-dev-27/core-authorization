import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Authorization DB schema.
 *
 * Hierarchy: User -> Business Unit / Utility -> Application -> Environment -> Module -> Role -> Permission
 *
 * SECURITY INVARIANT: this database never stores passwords, password hashes or
 * any credential material for end users. The ITS ID is the shared identity key
 * with the Authentication DB. (API keys for calling services are stored as
 * SHA-256 digests of high-entropy random secrets.)
 */
export class InitAuthorizationSchema1789300000000 implements MigrationInterface {
  name = 'InitAuthorizationSchema1789300000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE business_units (
        id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        code         varchar(64)  NOT NULL UNIQUE CHECK (code ~ '^[A-Z0-9][A-Z0-9_-]{1,63}$'),
        name         varchar(200) NOT NULL,
        description  text,
        status       varchar(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
        created_at   timestamptz  NOT NULL DEFAULT now(),
        updated_at   timestamptz  NOT NULL DEFAULT now()
      )`);

    await q.query(`
      CREATE TABLE utilities (
        id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        code             varchar(64)  NOT NULL UNIQUE CHECK (code ~ '^[A-Z0-9][A-Z0-9_-]{1,63}$'),
        name             varchar(200) NOT NULL,
        description      text,
        business_unit_id uuid REFERENCES business_units(id),
        status           varchar(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
        created_at       timestamptz  NOT NULL DEFAULT now(),
        updated_at       timestamptz  NOT NULL DEFAULT now()
      )`);

    await q.query(`
      CREATE TABLE environments (
        id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        code          varchar(16)  NOT NULL UNIQUE CHECK (code ~ '^[A-Z0-9_]{2,16}$'),
        name          varchar(100) NOT NULL,
        is_production boolean      NOT NULL DEFAULT false,
        sort_order    integer      NOT NULL DEFAULT 0,
        created_at    timestamptz  NOT NULL DEFAULT now()
      )`);

    await q.query(`
      CREATE TABLE applications (
        id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        code             varchar(64)  NOT NULL UNIQUE CHECK (code ~ '^[a-z0-9][a-z0-9-]{1,63}$'),
        name             varchar(200) NOT NULL,
        description      text,
        business_unit_id uuid REFERENCES business_units(id),
        utility_id       uuid REFERENCES utilities(id),
        status           varchar(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
        created_at       timestamptz  NOT NULL DEFAULT now(),
        updated_at       timestamptz  NOT NULL DEFAULT now(),
        CONSTRAINT applications_owner_chk CHECK (business_unit_id IS NOT NULL OR utility_id IS NOT NULL)
      )`);

    await q.query(`
      CREATE TABLE app_modules (
        id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
        code           varchar(64)  NOT NULL CHECK (code ~ '^[a-z0-9][a-z0-9_-]{1,63}$'),
        name           varchar(200) NOT NULL,
        description    text,
        status         varchar(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
        created_at     timestamptz  NOT NULL DEFAULT now(),
        updated_at     timestamptz  NOT NULL DEFAULT now(),
        UNIQUE (application_id, code)
      )`);

    await q.query(`
      CREATE TABLE permissions (
        id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        module_id   uuid NOT NULL REFERENCES app_modules(id) ON DELETE CASCADE,
        code        varchar(160) NOT NULL UNIQUE CHECK (code ~ '^[a-z0-9][a-z0-9_-]*(\\.[a-z0-9][a-z0-9_-]*){2,}$'),
        action      varchar(64)  NOT NULL,
        description text,
        status      varchar(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
        created_at  timestamptz  NOT NULL DEFAULT now(),
        updated_at  timestamptz  NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE INDEX idx_permissions_module ON permissions (module_id)`);

    await q.query(`
      CREATE TABLE roles (
        id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
        code           varchar(64)  NOT NULL CHECK (code ~ '^[A-Z0-9][A-Z0-9_]{1,63}$'),
        name           varchar(200) NOT NULL,
        description    text,
        status         varchar(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
        created_at     timestamptz  NOT NULL DEFAULT now(),
        updated_at     timestamptz  NOT NULL DEFAULT now(),
        UNIQUE (application_id, code)
      )`);

    await q.query(`
      CREATE TABLE role_permissions (
        role_id       uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
        granted_by    varchar(128),
        created_at    timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (role_id, permission_id)
      )`);

    await q.query(`
      CREATE TABLE users (
        id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        its_id              varchar(64)  NOT NULL UNIQUE CHECK (its_id ~ '^[A-Za-z0-9._-]{1,64}$'),
        identity_type       varchar(16)  NOT NULL DEFAULT 'ITS' CHECK (identity_type IN ('ITS', 'NON_ITS')),
        display_name        varchar(256),
        email               varchar(256),
        mobile              varchar(32),
        status              varchar(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE', 'SUSPENDED')),
        federation_user_ref varchar(64),
        last_synced_at      timestamptz,
        created_at          timestamptz  NOT NULL DEFAULT now(),
        updated_at          timestamptz  NOT NULL DEFAULT now()
      )`);

    await q.query(`
      CREATE TABLE user_application_access (
        id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
        environment_id uuid REFERENCES environments(id),
        status         varchar(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
        valid_from     timestamptz,
        valid_to       timestamptz,
        granted_by     varchar(128),
        created_at     timestamptz NOT NULL DEFAULT now(),
        updated_at     timestamptz NOT NULL DEFAULT now()
      )`);
    await q.query(`
      CREATE UNIQUE INDEX uq_user_application_access
        ON user_application_access (user_id, application_id, COALESCE(environment_id, '00000000-0000-0000-0000-000000000000'::uuid))`);

    await q.query(`
      CREATE TABLE user_roles (
        id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role_id        uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        environment_id uuid REFERENCES environments(id),
        status         varchar(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
        valid_from     timestamptz,
        valid_to       timestamptz,
        granted_by     varchar(128),
        created_at     timestamptz NOT NULL DEFAULT now(),
        updated_at     timestamptz NOT NULL DEFAULT now()
      )`);
    await q.query(`
      CREATE UNIQUE INDEX uq_user_roles
        ON user_roles (user_id, role_id, COALESCE(environment_id, '00000000-0000-0000-0000-000000000000'::uuid))`);

    await q.query(`
      CREATE TABLE clients (
        id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        client_id           varchar(64)  NOT NULL UNIQUE CHECK (client_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
        application_id      uuid NOT NULL REFERENCES applications(id),
        environment_id      uuid NOT NULL REFERENCES environments(id),
        name                varchar(200) NOT NULL,
        client_type         varchar(16)  NOT NULL CHECK (client_type IN ('WEB', 'SPA', 'MOBILE', 'SERVICE')),
        authentication_mode varchar(24)  NOT NULL CHECK (authentication_mode IN ('EMBEDDED', 'REDIRECT', 'EMBEDDED_OR_REDIRECT')),
        status              varchar(24)  NOT NULL DEFAULT 'PENDING'
                              CHECK (status IN ('PENDING', 'SECURITY_REVIEW', 'ACTIVE', 'SUSPENDED', 'RETIRED')),
        initiate_login_uri  varchar(2048),
        created_at          timestamptz  NOT NULL DEFAULT now(),
        updated_at          timestamptz  NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE INDEX idx_clients_application_env ON clients (application_id, environment_id)`);

    await q.query(`
      CREATE TABLE client_origins (
        id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        client_ref uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        origin     varchar(512) NOT NULL CHECK (origin !~ '\\*'),
        purpose    varchar(16)  NOT NULL DEFAULT 'EMBED' CHECK (purpose IN ('EMBED')),
        created_by varchar(128),
        created_at timestamptz  NOT NULL DEFAULT now(),
        UNIQUE (client_ref, origin, purpose)
      )`);

    await q.query(`
      CREATE TABLE client_redirect_uris (
        id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        client_ref uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        uri        varchar(2048) NOT NULL CHECK (uri !~ '\\*'),
        uri_type   varchar(32)   NOT NULL CHECK (uri_type IN ('CALLBACK', 'BACK_CHANNEL_LOGOUT', 'POST_LOGOUT_REDIRECT')),
        is_primary boolean       NOT NULL DEFAULT false,
        created_by varchar(128),
        created_at timestamptz   NOT NULL DEFAULT now(),
        UNIQUE (client_ref, uri, uri_type)
      )`);
    await q.query(`
      CREATE UNIQUE INDEX uq_client_single_backchannel
        ON client_redirect_uris (client_ref) WHERE uri_type = 'BACK_CHANNEL_LOGOUT'`);

    await q.query(`
      CREATE TABLE client_status_history (
        id          bigserial PRIMARY KEY,
        client_ref  uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        from_status varchar(24),
        to_status   varchar(24) NOT NULL,
        reason      text,
        changed_by  varchar(128),
        changed_at  timestamptz NOT NULL DEFAULT now()
      )`);

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

    await q.query(`
      CREATE TABLE authorization_audit_logs (
        id             bigserial PRIMARY KEY,
        event_type     varchar(64) NOT NULL,
        actor          varchar(128),
        its_id         varchar(64),
        client_id      varchar(64),
        resource_type  varchar(64),
        resource_id    varchar(256),
        decision       varchar(16),
        reason         varchar(64),
        correlation_id varchar(128),
        metadata       jsonb,
        created_at     timestamptz NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE INDEX idx_authz_audit_its ON authorization_audit_logs (its_id, created_at DESC)`);
    await q.query(`CREATE INDEX idx_authz_audit_client ON authorization_audit_logs (client_id, created_at DESC)`);
    await q.query(`CREATE INDEX idx_authz_audit_event ON authorization_audit_logs (event_type, created_at DESC)`);
  }

  public async down(q: QueryRunner): Promise<void> {
    for (const table of [
      'authorization_audit_logs',
      'api_clients',
      'client_status_history',
      'client_redirect_uris',
      'client_origins',
      'clients',
      'user_roles',
      'user_application_access',
      'users',
      'role_permissions',
      'roles',
      'permissions',
      'app_modules',
      'applications',
      'environments',
      'utilities',
      'business_units',
    ]) {
      await q.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
    }
  }
}
