import { MigrationInterface, QueryRunner } from 'typeorm';

const S = 'miqaat_core';

/**
 * Miqaat Core Platform — Core Admin Control Panel data model (miqaat_core_db, Batch 1).
 *
 * Created in its own PostgreSQL schema `miqaat_core`, next to (and independent of) the existing `public`
 * tables used by the Authorization service, which are left unchanged.
 *
 *   File 1: tenants, tenant_domains, tenant_domain_credentials, tenant_core_credentials, platform_settings, tenant_rate_limits
 *   File 2: modules, permission_actions, module_actions, roles, role_permissions
 *   File 3: users, user_roles
 *
 * Not implemented in this batch: login (user_sessions, login_otp_codes) and Non-ITS members — users.its_id is
 * therefore required and must be an 8-digit ITS ID.
 *
 * Reversible: down() drops the whole schema.
 */
export class MiqaatCoreSchema1789600000000 implements MigrationInterface {
  name = 'MiqaatCoreSchema1789600000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`CREATE SCHEMA IF NOT EXISTS ${S}`);

    await q.query(`
      CREATE OR REPLACE FUNCTION ${S}.set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        NEW.updated_at = now();
        RETURN NEW;
      END $$`);

    // ------------------------------------------------------------------ enums (declared in flow order)
    const enums: Record<string, string[]> = {
      tenant_type: ['BUSINESS_UNIT', 'UTILITY'],
      tenant_status: ['ACTIVE', 'INACTIVE'],
      auth_header_type: ['AUTHORIZATION', 'X_API_KEY', 'CUSTOM'],
      config_duration_unit: ['MINUTES', 'HOURS', 'DAYS', 'WEEKS', 'MONTHS'],
      rate_limit_quota_period: ['PER_DAY', 'PER_MONTH'],
      onboarding_stage: ['WELCOME', 'VERIFY_DETAILS', 'PROVIDE_KEY', 'VERIFY_CONNECTION', 'COMPLETED'],
      role_level: ['CORE_ADMIN', 'BUSINESS_UNIT_ADMIN', 'UTILITY_ADMIN'],
      role_status: ['ACTIVE', 'INACTIVE'],
      user_status: ['INVITED', 'ACTIVE', 'DISABLED'],
    };
    for (const [name, values] of Object.entries(enums)) {
      await q.query(`CREATE TYPE ${S}.${name} AS ENUM (${values.map((v) => `'${v}'`).join(', ')})`);
    }

    // ------------------------------------------------------------------ users (ITS members only in this batch)
    await q.query(`
      CREATE TABLE ${S}.users (
        id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        its_id          varchar(8)   NOT NULL UNIQUE,
        name            varchar(255) NOT NULL,
        email           varchar(255) NOT NULL UNIQUE,
        mobile_number   varchar(30),
        status          ${S}.user_status NOT NULL DEFAULT 'INVITED',
        has_been_active boolean      NOT NULL DEFAULT false,
        last_login_at   timestamptz,
        created_by      uuid REFERENCES ${S}.users (id) ON DELETE SET NULL,
        updated_by      uuid REFERENCES ${S}.users (id) ON DELETE SET NULL,
        created_at      timestamptz  NOT NULL DEFAULT now(),
        updated_at      timestamptz  NOT NULL DEFAULT now(),
        CONSTRAINT ck_users_its_id_8_digits CHECK (its_id ~ '^[0-9]{8}$'),
        CONSTRAINT ck_users_name_not_blank CHECK (length(trim(name)) > 0),
        CONSTRAINT ck_users_active_has_been_active CHECK (status <> 'ACTIVE' OR has_been_active)
      )`);
    await q.query(`COMMENT ON TABLE ${S}.users IS 'One row per person (ITS members only in this batch). Role assignments live in user_roles.'`);

    // ------------------------------------------------------------------ file 1: tenants and domains
    await q.query(`
      CREATE TABLE ${S}.tenants (
        id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_type      ${S}.tenant_type      NOT NULL,
        name             varchar(255)          NOT NULL,
        description      text,
        status           ${S}.tenant_status    NOT NULL DEFAULT 'ACTIVE',
        onboarding_stage ${S}.onboarding_stage NOT NULL DEFAULT 'WELCOME',
        created_by       uuid REFERENCES ${S}.users (id) ON DELETE SET NULL,
        updated_by       uuid REFERENCES ${S}.users (id) ON DELETE SET NULL,
        created_at       timestamptz NOT NULL DEFAULT now(),
        updated_at       timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT ck_tenants_name_not_blank CHECK (length(trim(name)) > 0)
      )`);
    await q.query(`CREATE UNIQUE INDEX uq_tenants_type_name_ci ON ${S}.tenants (tenant_type, lower(trim(name)))`);
    await q.query(`COMMENT ON TABLE ${S}.tenants IS 'Business Units and Utilities in one registry (tenant_type); a Utility is never nested under a Business Unit.'`);

    await q.query(`
      CREATE TABLE ${S}.tenant_domains (
        id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id          uuid NOT NULL REFERENCES ${S}.tenants (id) ON DELETE CASCADE,
        url                varchar(500) NOT NULL,
        is_default         boolean NOT NULL DEFAULT false,
        auth_header_type   ${S}.auth_header_type NOT NULL DEFAULT 'AUTHORIZATION',
        custom_header_name varchar(255),
        label              varchar(255),
        created_at         timestamptz NOT NULL DEFAULT now(),
        updated_at         timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT ck_tenant_domains_custom_header CHECK (auth_header_type <> 'CUSTOM' OR length(trim(coalesce(custom_header_name, ''))) > 0)
      )`);
    await q.query(`CREATE INDEX ix_tenant_domains_tenant_id ON ${S}.tenant_domains (tenant_id)`);
    await q.query(`CREATE UNIQUE INDEX uq_tenant_domains_one_default ON ${S}.tenant_domains (tenant_id) WHERE is_default`);

    await q.query(`
      CREATE TABLE ${S}.tenant_domain_credentials (
        id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_domain_id           uuid NOT NULL UNIQUE REFERENCES ${S}.tenant_domains (id) ON DELETE CASCADE,
        access_token_value         text NOT NULL,
        health_check_path          varchar(500),
        use_token_for_health_check boolean NOT NULL DEFAULT false,
        last_verified_at           timestamptz,
        created_at                 timestamptz NOT NULL DEFAULT now(),
        updated_at                 timestamptz NOT NULL DEFAULT now()
      )`);
    await q.query(`COMMENT ON COLUMN ${S}.tenant_domain_credentials.access_token_value IS 'Reciprocal tenant key. Store an encrypted / secrets-manager value, never plaintext.'`);

    await q.query(`
      CREATE TABLE ${S}.tenant_core_credentials (
        id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id           uuid NOT NULL UNIQUE REFERENCES ${S}.tenants (id) ON DELETE CASCADE,
        core_access_token   text NOT NULL,
        aws_api_key_id      varchar(64),
        security_access_key text NOT NULL,
        security_secret_key text NOT NULL,
        standard_queue_arn  text NOT NULL,
        fifo_queue_arn      text NOT NULL,
        relay_hmac_secret   text NOT NULL,
        created_at          timestamptz NOT NULL DEFAULT now()
      )`);
    await q.query(`COMMENT ON TABLE ${S}.tenant_core_credentials IS 'Generated once when the tenant is created; read-only afterwards. Secret columns hold encrypted / secrets-manager values.'`);

    await q.query(`
      CREATE TABLE ${S}.platform_settings (
        id                                            integer PRIMARY KEY DEFAULT 1,
        event_bus_name                                varchar(255) NOT NULL,
        event_bus_arn                                 text NOT NULL,
        timezone                                      varchar(64) NOT NULL DEFAULT 'UTC',
        max_admins_per_tenant                         integer NOT NULL DEFAULT 1,
        audit_log_archival_duration_value             integer NOT NULL DEFAULT 90,
        audit_log_archival_duration_unit              ${S}.config_duration_unit NOT NULL DEFAULT 'DAYS',
        monitoring_log_archival_duration_value        integer NOT NULL DEFAULT 60,
        monitoring_log_archival_duration_unit         ${S}.config_duration_unit NOT NULL DEFAULT 'DAYS',
        contract_deprecation_duration_value           integer NOT NULL DEFAULT 30,
        contract_deprecation_duration_unit            ${S}.config_duration_unit NOT NULL DEFAULT 'DAYS',
        its_sync_frequency_value                      integer NOT NULL DEFAULT 6,
        its_sync_frequency_unit                       ${S}.config_duration_unit NOT NULL DEFAULT 'HOURS',
        core_rate_limit_per_second                    integer NOT NULL,
        core_rate_limit_burst                         integer NOT NULL,
        core_quota_enabled                            boolean NOT NULL DEFAULT false,
        core_quota_requests                           integer,
        core_quota_period                             ${S}.rate_limit_quota_period,
        circuit_breaker_probe_interval_value          integer NOT NULL DEFAULT 1,
        circuit_breaker_probe_interval_unit           ${S}.config_duration_unit NOT NULL DEFAULT 'MINUTES',
        circuit_breaker_open_cooldown_value           integer NOT NULL DEFAULT 2,
        circuit_breaker_open_cooldown_unit            ${S}.config_duration_unit NOT NULL DEFAULT 'MINUTES',
        circuit_breaker_failure_rate_threshold_pct    integer NOT NULL DEFAULT 50,
        circuit_breaker_min_sample_size               integer NOT NULL DEFAULT 10,
        circuit_breaker_consecutive_failure_threshold integer NOT NULL DEFAULT 3,
        default_sla_timeout_seconds                   integer NOT NULL,
        max_sla_timeout_seconds                       integer NOT NULL,
        updated_at                                    timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT ck_platform_settings_singleton CHECK (id = 1),
        CONSTRAINT ck_platform_settings_positive CHECK (
          max_admins_per_tenant >= 0
          AND audit_log_archival_duration_value > 0 AND monitoring_log_archival_duration_value > 0
          AND contract_deprecation_duration_value > 0 AND its_sync_frequency_value > 0
          AND core_rate_limit_per_second > 0 AND core_rate_limit_burst > 0
          AND circuit_breaker_probe_interval_value > 0 AND circuit_breaker_open_cooldown_value > 0
          AND circuit_breaker_min_sample_size > 0 AND circuit_breaker_consecutive_failure_threshold > 0),
        CONSTRAINT ck_platform_settings_core_quota CHECK (
          NOT core_quota_enabled OR (core_quota_requests > 0 AND core_quota_period IS NOT NULL)),
        CONSTRAINT ck_platform_settings_failure_rate CHECK (circuit_breaker_failure_rate_threshold_pct BETWEEN 1 AND 100),
        CONSTRAINT ck_platform_settings_sla CHECK (
          max_sla_timeout_seconds BETWEEN 1 AND 28 AND default_sla_timeout_seconds BETWEEN 1 AND max_sla_timeout_seconds)
      )`);
    await q.query(`COMMENT ON TABLE ${S}.platform_settings IS 'Singleton (id = 1): platform-wide Core Admin configuration (FR-13.1).'`);

    await q.query(`
      CREATE TABLE ${S}.tenant_rate_limits (
        id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id               uuid NOT NULL UNIQUE REFERENCES ${S}.tenants (id) ON DELETE CASCADE,
        rate_limit_per_second   integer NOT NULL,
        burst_limit             integer NOT NULL,
        quota_enabled           boolean NOT NULL DEFAULT false,
        quota_requests          integer,
        quota_period            ${S}.rate_limit_quota_period,
        max_sla_timeout_seconds integer,
        aws_usage_plan_id       varchar(64),
        created_at              timestamptz NOT NULL DEFAULT now(),
        updated_at              timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT ck_tenant_rate_limits_positive CHECK (rate_limit_per_second > 0 AND burst_limit > 0),
        CONSTRAINT ck_tenant_rate_limits_quota CHECK (NOT quota_enabled OR (quota_requests > 0 AND quota_period IS NOT NULL)),
        CONSTRAINT ck_tenant_rate_limits_sla CHECK (max_sla_timeout_seconds IS NULL OR max_sla_timeout_seconds BETWEEN 1 AND 28)
      )`);

    // ------------------------------------------------------------------ file 2: modules, roles, permission matrix
    await q.query(`
      CREATE TABLE ${S}.modules (
        id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        code              varchar(20)  NOT NULL UNIQUE,
        name              varchar(255) NOT NULL,
        applies_to_core   boolean NOT NULL DEFAULT false,
        applies_to_tenant boolean NOT NULL DEFAULT false,
        display_order     integer NOT NULL DEFAULT 0,
        created_at        timestamptz NOT NULL DEFAULT now()
      )`);

    await q.query(`
      CREATE TABLE ${S}.permission_actions (
        id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        code          varchar(20)  NOT NULL UNIQUE,
        name          varchar(100) NOT NULL,
        display_order integer NOT NULL DEFAULT 0,
        created_at    timestamptz NOT NULL DEFAULT now()
      )`);

    await q.query(`
      CREATE TABLE ${S}.module_actions (
        id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        module_id         uuid NOT NULL REFERENCES ${S}.modules (id) ON DELETE CASCADE,
        action_id         uuid NOT NULL REFERENCES ${S}.permission_actions (id) ON DELETE RESTRICT,
        applies_to_core   boolean NOT NULL DEFAULT true,
        applies_to_tenant boolean NOT NULL DEFAULT true,
        display_order     integer NOT NULL DEFAULT 0,
        created_at        timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT uq_module_actions_module_action UNIQUE (module_id, action_id)
      )`);

    await q.query(`
      CREATE TABLE ${S}.roles (
        id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        role_level            ${S}.role_level NOT NULL,
        tenant_id             uuid REFERENCES ${S}.tenants (id) ON DELETE CASCADE,
        role_code             varchar(50)  NOT NULL UNIQUE,
        name                  varchar(255) NOT NULL,
        description           text,
        status                ${S}.role_status NOT NULL DEFAULT 'ACTIVE',
        is_full_access        boolean NOT NULL DEFAULT false,
        created_by_core_admin boolean NOT NULL GENERATED ALWAYS AS (role_level = 'CORE_ADMIN' OR is_full_access) STORED,
        created_by            uuid REFERENCES ${S}.users (id) ON DELETE SET NULL,
        updated_by            uuid REFERENCES ${S}.users (id) ON DELETE SET NULL,
        created_at            timestamptz NOT NULL DEFAULT now(),
        updated_at            timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT ck_roles_tenant_scope CHECK ((tenant_id IS NULL) = (role_level = 'CORE_ADMIN')),
        CONSTRAINT ck_roles_role_code_format CHECK (role_code ~ '^role-[a-z0-9]+(-[a-z0-9]+)*$'),
        CONSTRAINT ck_roles_name_not_blank CHECK (length(trim(name)) > 0)
      )`);
    await q.query(`CREATE INDEX ix_roles_tenant_id ON ${S}.roles (tenant_id)`);
    await q.query(`CREATE INDEX ix_roles_level_tenant ON ${S}.roles (role_level, tenant_id)`);
    await q.query(`CREATE UNIQUE INDEX uq_roles_one_core_full_access ON ${S}.roles (role_level) WHERE is_full_access AND role_level = 'CORE_ADMIN'`);
    await q.query(`CREATE UNIQUE INDEX uq_roles_one_full_access_per_tenant ON ${S}.roles (tenant_id) WHERE is_full_access AND tenant_id IS NOT NULL`);
    await q.query(`CREATE INDEX ix_roles_created_by_core_admin ON ${S}.roles (role_level) WHERE created_by_core_admin`);

    // A Business Unit Admin-level role belongs to a BUSINESS_UNIT tenant, a Utility Admin-level role to a UTILITY tenant.
    await q.query(`
      CREATE OR REPLACE FUNCTION ${S}.roles_check_tenant_type() RETURNS trigger LANGUAGE plpgsql AS $$
      DECLARE t ${S}.tenant_type;
      BEGIN
        IF NEW.tenant_id IS NULL THEN RETURN NEW; END IF;
        SELECT tenant_type INTO t FROM ${S}.tenants WHERE id = NEW.tenant_id;
        IF (NEW.role_level = 'BUSINESS_UNIT_ADMIN' AND t <> 'BUSINESS_UNIT') OR (NEW.role_level = 'UTILITY_ADMIN' AND t <> 'UTILITY') THEN
          RAISE EXCEPTION 'role level % does not match tenant type %', NEW.role_level, t USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END $$`);
    await q.query(`CREATE TRIGGER trg_roles_check_tenant_type BEFORE INSERT OR UPDATE OF role_level, tenant_id ON ${S}.roles FOR EACH ROW EXECUTE FUNCTION ${S}.roles_check_tenant_type()`);

    await q.query(`
      CREATE TABLE ${S}.role_permissions (
        id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        role_id          uuid NOT NULL REFERENCES ${S}.roles (id) ON DELETE CASCADE,
        module_action_id uuid NOT NULL REFERENCES ${S}.module_actions (id) ON DELETE RESTRICT,
        created_at       timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT uq_role_permissions_role_module_action UNIQUE (role_id, module_action_id)
      )`);

    // A checkbox can only be granted where the matrix offers it for the role's level (module AND module_action flags).
    await q.query(`
      CREATE OR REPLACE FUNCTION ${S}.role_permissions_check_level() RETURNS trigger LANGUAGE plpgsql AS $$
      DECLARE lvl ${S}.role_level; offered boolean;
      BEGIN
        SELECT role_level INTO lvl FROM ${S}.roles WHERE id = NEW.role_id;
        SELECT CASE WHEN lvl = 'CORE_ADMIN' THEN m.applies_to_core AND ma.applies_to_core
                    ELSE m.applies_to_tenant AND ma.applies_to_tenant END
          INTO offered
          FROM ${S}.module_actions ma JOIN ${S}.modules m ON m.id = ma.module_id
         WHERE ma.id = NEW.module_action_id;
        IF NOT coalesce(offered, false) THEN
          RAISE EXCEPTION 'module action is not offered for role level %', lvl USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END $$`);
    await q.query(`CREATE TRIGGER trg_role_permissions_check_level BEFORE INSERT OR UPDATE ON ${S}.role_permissions FOR EACH ROW EXECUTE FUNCTION ${S}.role_permissions_check_level()`);

    // ------------------------------------------------------------------ file 3: role assignment
    await q.query(`
      CREATE TABLE ${S}.user_roles (
        id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id     uuid NOT NULL REFERENCES ${S}.users (id) ON DELETE CASCADE,
        role_id     uuid NOT NULL REFERENCES ${S}.roles (id) ON DELETE CASCADE,
        tenant_id   uuid REFERENCES ${S}.tenants (id) ON DELETE CASCADE,
        role_level  ${S}.role_level NOT NULL,
        assigned_by uuid REFERENCES ${S}.users (id) ON DELETE SET NULL,
        assigned_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT uq_user_roles_user_role UNIQUE (user_id, role_id)
      )`);
    await q.query(`CREATE UNIQUE INDEX uq_user_roles_one_role_per_tenant ON ${S}.user_roles (user_id, tenant_id) WHERE tenant_id IS NOT NULL`);
    await q.query(`CREATE UNIQUE INDEX uq_user_roles_one_core_admin_role ON ${S}.user_roles (user_id) WHERE role_level = 'CORE_ADMIN'`);

    // tenant_id / role_level are copies of the assigned role's values, taken at assignment time.
    await q.query(`
      CREATE OR REPLACE FUNCTION ${S}.user_roles_copy_role() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        SELECT tenant_id, role_level INTO NEW.tenant_id, NEW.role_level FROM ${S}.roles WHERE id = NEW.role_id;
        RETURN NEW;
      END $$`);
    await q.query(`CREATE TRIGGER trg_user_roles_copy_role BEFORE INSERT OR UPDATE OF role_id, tenant_id, role_level ON ${S}.user_roles FOR EACH ROW EXECUTE FUNCTION ${S}.user_roles_copy_role()`);

    // ------------------------------------------------------------------ updated_at maintenance
    for (const table of ['users', 'tenants', 'tenant_domains', 'tenant_domain_credentials', 'platform_settings', 'tenant_rate_limits', 'roles']) {
      await q.query(`CREATE TRIGGER trg_${table}_updated_at BEFORE UPDATE ON ${S}.${table} FOR EACH ROW EXECUTE FUNCTION ${S}.set_updated_at()`);
    }

    // ------------------------------------------------------------------ reference data
    await q.query(`
      INSERT INTO ${S}.permission_actions (code, name, display_order) VALUES
        ('CREATE', 'Create', 1), ('READ', 'Read', 2), ('UPDATE', 'Update', 3), ('APPROVE', 'Approval', 4)`);

    // Role-wise Module Access (v2 section 5): BUM, UTM, MUM are Core-only; the rest apply to every level.
    await q.query(`
      INSERT INTO ${S}.modules (code, name, applies_to_core, applies_to_tenant, display_order) VALUES
        ('ROLE', 'Role Management',                       true, true,  1),
        ('USR',  'User Management',                       true, true,  2),
        ('BUM',  'Business Unit Management',              true, false, 3),
        ('UTM',  'Utility Management',                    true, false, 4),
        ('CFG',  'Configuration',                         true, true,  5),
        ('MUM',  'Mumin Information',                     true, false, 6),
        ('DCE',  'Data Contract & Exchange Management',   true, true,  7),
        ('MON',  'Monitoring',                            true, true,  8),
        ('AUD',  'Audit Log',                             true, true,  9),
        ('TKT',  'Ticket Management',                     true, true,  10)`);

    // Every module x {CREATE, READ, UPDATE} except CFG x CREATE; DCE x APPROVE for tenant-level roles only.
    await q.query(`
      INSERT INTO ${S}.module_actions (module_id, action_id, applies_to_core, applies_to_tenant, display_order)
      SELECT m.id, a.id, m.applies_to_core, m.applies_to_tenant, a.display_order
        FROM ${S}.modules m CROSS JOIN ${S}.permission_actions a
       WHERE a.code IN ('CREATE', 'READ', 'UPDATE')
         AND NOT (m.code = 'CFG' AND a.code = 'CREATE')`);
    await q.query(`
      INSERT INTO ${S}.module_actions (module_id, action_id, applies_to_core, applies_to_tenant, display_order)
      SELECT m.id, a.id, false, true, a.display_order
        FROM ${S}.modules m, ${S}.permission_actions a
       WHERE m.code = 'DCE' AND a.code = 'APPROVE'`);

    // The single platform-wide locked Core Admin role, holding every checkbox offered at Core level.
    await q.query(`
      INSERT INTO ${S}.roles (role_level, tenant_id, role_code, name, description, is_full_access)
      VALUES ('CORE_ADMIN', NULL, 'role-platform-administrator', 'Platform Administrator', 'Full access to every Core Admin module.', true)`);
    await q.query(`
      INSERT INTO ${S}.role_permissions (role_id, module_action_id)
      SELECT r.id, ma.id
        FROM ${S}.roles r
        JOIN ${S}.module_actions ma ON ma.applies_to_core
        JOIN ${S}.modules m ON m.id = ma.module_id AND m.applies_to_core
       WHERE r.role_code = 'role-platform-administrator'`);
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP SCHEMA IF EXISTS ${S} CASCADE`);
  }
}
