import { MigrationInterface, QueryRunner } from 'typeorm';

const NIL = `'00000000-0000-0000-0000-000000000000'::uuid`;

/**
 * MIQAAT CORE — Role & Permission Module schema.
 *
 * tenants → business_units → utilities; users (ITS ID is the PK); modules → permissions;
 * roles (scope_level CORE | BUSINESS_UNIT | UTILITY) ↔ role_permissions; user_roles (role × scope).
 * Applications / environments / clients are kept for the login federation; an application is owned by a
 * business unit, a utility or (Core Portal) the tenant, and its own permissions live in non-default modules.
 *
 * Every table has created_at + updated_at (maintained by trigger). No passwords are stored in this database.
 * This migration replaces the earlier per-application RBAC tables and is not reversible.
 */
export class CoreRbacSchema1789500000000 implements MigrationInterface {
  name = 'CoreRbacSchema1789500000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        NEW.updated_at = now();
        RETURN NEW;
      END $$`);

    for (const table of [
      'client_status_history', 'client_redirect_uris', 'client_origins', 'clients', 'user_roles', 'user_application_access',
      'role_permissions', 'roles', 'permissions', 'app_modules', 'applications', 'users', 'utilities', 'business_units',
    ]) {
      await q.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
    }

    await q.query(`
      CREATE TABLE tenants (
        tenant_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        name       varchar(200) NOT NULL UNIQUE,
        status     varchar(16)  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
        created_at timestamptz  NOT NULL DEFAULT now(),
        updated_at timestamptz  NOT NULL DEFAULT now()
      )`);

    await q.query(`
      CREATE TABLE business_units (
        bu_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id  uuid NOT NULL REFERENCES tenants(tenant_id),
        name       varchar(200) NOT NULL,
        status     varchar(16)  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
        created_at timestamptz  NOT NULL DEFAULT now(),
        updated_at timestamptz  NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, name)
      )`);

    await q.query(`
      CREATE TABLE utilities (
        utility_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        bu_id      uuid NOT NULL REFERENCES business_units(bu_id),
        name       varchar(200) NOT NULL,
        status     varchar(16)  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
        created_at timestamptz  NOT NULL DEFAULT now(),
        updated_at timestamptz  NOT NULL DEFAULT now(),
        UNIQUE (bu_id, name)
      )`);

    await q.query(`
      CREATE TABLE users (
        its_id     varchar(64)  PRIMARY KEY CHECK (its_id ~ '^[A-Za-z0-9._-]{1,64}$'),
        tenant_id  uuid NOT NULL REFERENCES tenants(tenant_id),
        name       varchar(256) NOT NULL,
        email      varchar(256),
        status     varchar(16)  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
        created_at timestamptz  NOT NULL DEFAULT now(),
        updated_at timestamptz  NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE INDEX idx_users_tenant ON users (tenant_id)`);

    await q.query(`
      CREATE TABLE applications (
        application_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id      uuid NOT NULL REFERENCES tenants(tenant_id),
        bu_id          uuid REFERENCES business_units(bu_id),
        utility_id     uuid REFERENCES utilities(utility_id),
        code           varchar(64)  NOT NULL UNIQUE CHECK (code ~ '^[a-z0-9][a-z0-9-]{1,63}$'),
        name           varchar(200) NOT NULL,
        description    text,
        status         varchar(16)  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
        created_at     timestamptz  NOT NULL DEFAULT now(),
        updated_at     timestamptz  NOT NULL DEFAULT now(),
        CONSTRAINT applications_single_owner CHECK (bu_id IS NULL OR utility_id IS NULL)
      )`);

    await q.query(`
      CREATE TABLE modules (
        module_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        module_code    varchar(64)  NOT NULL UNIQUE CHECK (module_code ~ '^[A-Z][A-Z0-9_]{1,63}$'),
        module_name    varchar(200) NOT NULL,
        is_default     boolean      NOT NULL DEFAULT false,
        application_id uuid REFERENCES applications(application_id) ON DELETE CASCADE,
        created_at     timestamptz  NOT NULL DEFAULT now(),
        updated_at     timestamptz  NOT NULL DEFAULT now()
      )`);
    await q.query(`COMMENT ON COLUMN modules.application_id IS 'NULL = Core Portal module (the 14 defaults); otherwise the application that owns the module'`);

    await q.query(`
      CREATE TABLE permissions (
        permission_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        module_id       uuid NOT NULL REFERENCES modules(module_id) ON DELETE CASCADE,
        action          varchar(16)  NOT NULL CHECK (action IN ('view', 'create', 'edit', 'delete', 'approve', 'export')),
        permission_code varchar(128) NOT NULL UNIQUE CHECK (permission_code ~ '^[A-Z][A-Z0-9_]{1,127}$'),
        created_at      timestamptz  NOT NULL DEFAULT now(),
        updated_at      timestamptz  NOT NULL DEFAULT now(),
        UNIQUE (module_id, action)
      )`);

    await q.query(`
      CREATE TABLE roles (
        role_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id      uuid NOT NULL REFERENCES tenants(tenant_id),
        role_name      varchar(200) NOT NULL,
        scope_level    varchar(16)  NOT NULL CHECK (scope_level IN ('CORE', 'BUSINESS_UNIT', 'UTILITY')),
        is_system_role boolean      NOT NULL DEFAULT false,
        created_at     timestamptz  NOT NULL DEFAULT now(),
        updated_at     timestamptz  NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, role_name)
      )`);

    await q.query(`
      CREATE TABLE role_permissions (
        role_id       uuid NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
        permission_id uuid NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
        created_at    timestamptz NOT NULL DEFAULT now(),
        updated_at    timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (role_id, permission_id)
      )`);

    // PostgreSQL primary keys cannot contain the nullable scope_id (NULL for CORE), so the composite key
    // (its_id, role_id, scope_id) is enforced by a unique index that treats NULL as a single CORE value.
    await q.query(`
      CREATE TABLE user_roles (
        its_id      varchar(64) NOT NULL REFERENCES users(its_id) ON DELETE CASCADE,
        role_id     uuid        NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
        scope_type  varchar(16) NOT NULL CHECK (scope_type IN ('CORE', 'BUSINESS_UNIT', 'UTILITY')),
        scope_id    uuid,
        assigned_at timestamptz NOT NULL DEFAULT now(),
        created_at  timestamptz NOT NULL DEFAULT now(),
        updated_at  timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT user_roles_scope_id_matches_type CHECK ((scope_type = 'CORE') = (scope_id IS NULL))
      )`);
    await q.query(`CREATE UNIQUE INDEX uq_user_roles ON user_roles (its_id, role_id, (COALESCE(scope_id, ${NIL})))`);
    await q.query(`CREATE INDEX idx_user_roles_scope ON user_roles (scope_type, scope_id)`);

    // Referential integrity for the polymorphic scope_id + role level / tenant consistency.
    await q.query(`
      CREATE OR REPLACE FUNCTION check_user_role_scope() RETURNS trigger LANGUAGE plpgsql AS $$
      DECLARE
        role_level   varchar;
        role_tenant  uuid;
        user_tenant  uuid;
        scope_tenant uuid;
      BEGIN
        SELECT scope_level, tenant_id INTO role_level, role_tenant FROM roles WHERE role_id = NEW.role_id;
        IF role_level IS DISTINCT FROM NEW.scope_type THEN
          RAISE EXCEPTION 'scope_type % does not match role scope_level %', NEW.scope_type, role_level USING ERRCODE = '23514';
        END IF;
        SELECT tenant_id INTO user_tenant FROM users WHERE its_id = NEW.its_id;
        IF user_tenant IS DISTINCT FROM role_tenant THEN
          RAISE EXCEPTION 'user and role belong to different tenants' USING ERRCODE = '23514';
        END IF;
        IF NEW.scope_type = 'BUSINESS_UNIT' THEN
          SELECT tenant_id INTO scope_tenant FROM business_units WHERE bu_id = NEW.scope_id;
        ELSIF NEW.scope_type = 'UTILITY' THEN
          SELECT bu.tenant_id INTO scope_tenant FROM utilities u JOIN business_units bu ON bu.bu_id = u.bu_id WHERE u.utility_id = NEW.scope_id;
        ELSE
          scope_tenant := role_tenant;
        END IF;
        IF scope_tenant IS NULL OR scope_tenant <> role_tenant THEN
          RAISE EXCEPTION 'scope % % not found in the role tenant', NEW.scope_type, NEW.scope_id USING ERRCODE = '23503';
        END IF;
        RETURN NEW;
      END $$`);
    await q.query(`CREATE TRIGGER trg_user_roles_scope BEFORE INSERT OR UPDATE ON user_roles FOR EACH ROW EXECUTE FUNCTION check_user_role_scope()`);

    // Federation registry (unchanged semantics; re-created against applications.application_id).
    await q.query(`
      CREATE TABLE clients (
        id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        client_id           varchar(64)  NOT NULL UNIQUE CHECK (client_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
        application_id      uuid NOT NULL REFERENCES applications(application_id),
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
        updated_at timestamptz  NOT NULL DEFAULT now(),
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
        updated_at timestamptz   NOT NULL DEFAULT now(),
        UNIQUE (client_ref, uri, uri_type)
      )`);
    await q.query(`CREATE UNIQUE INDEX uq_client_single_backchannel ON client_redirect_uris (client_ref) WHERE uri_type = 'BACK_CHANNEL_LOGOUT'`);

    await q.query(`
      CREATE TABLE client_status_history (
        id          bigserial PRIMARY KEY,
        client_ref  uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        from_status varchar(24),
        to_status   varchar(24) NOT NULL,
        reason      text,
        changed_by  varchar(128),
        changed_at  timestamptz NOT NULL DEFAULT now(),
        created_at  timestamptz NOT NULL DEFAULT now(),
        updated_at  timestamptz NOT NULL DEFAULT now()
      )`);

    await q.query(`ALTER TABLE environments ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()`);
    await q.query(`ALTER TABLE authorization_audit_logs ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()`);

    for (const table of [
      'tenants', 'business_units', 'utilities', 'users', 'applications', 'modules', 'permissions', 'roles', 'role_permissions',
      'user_roles', 'clients', 'client_origins', 'client_redirect_uris', 'client_status_history', 'environments',
      'authorization_audit_logs', 'service_principals',
    ]) {
      await q.query(`DROP TRIGGER IF EXISTS trg_${table}_updated_at ON ${table}`);
      await q.query(`CREATE TRIGGER trg_${table}_updated_at BEFORE UPDATE ON ${table} FOR EACH ROW EXECUTE FUNCTION set_updated_at()`);
    }
  }

  public async down(): Promise<void> {
    throw new Error('CoreRbacSchema1789500000000 replaces the previous RBAC model and cannot be reverted automatically; restore from backup.');
  }
}
