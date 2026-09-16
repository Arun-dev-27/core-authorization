/**
 * Integration tests for the miqaat_core schema (Core Admin Control Panel data model, Batch 1) against real PostgreSQL.
 * Only rows in miqaat_core are created and removed; the Authorization service's public tables are not touched.
 * Run: npm run infra:up && npm run test:e2e
 */
import { DataSource } from 'typeorm';
import { loadEnv } from '@config/configuration';
import { buildDataSourceOptions } from '@core/database/data-source-options';

const S = 'miqaat_core';
const PLATFORM_ROLE = 'role-platform-administrator';
let db: DataSource;

const rows = <T = Record<string, unknown>>(sql: string, params: unknown[] = []) => db.query(sql, params) as Promise<T[]>;
const one = async <T = Record<string, unknown>>(sql: string, params: unknown[] = []) => (await rows<T>(sql, params))[0];
/** Postgres SQLSTATE of a failing statement (23505 unique, 23514 check, 23503 foreign key, 23502 not null, 428C9 generated column). */
const errorCode = async (sql: string, params: unknown[] = []) => {
  try {
    await db.query(sql, params);
  } catch (error) {
    return (error as { code?: string }).code;
  }
  return 'NO_ERROR';
};

let seq = 0;
const itsId = () => String(40000000 + ++seq);
const createUser = async (overrides: Record<string, unknown> = {}) =>
  (await one<{ id: string }>(`INSERT INTO ${S}.users (its_id, name, email) VALUES ($1, $2, $3) RETURNING id`, [
    overrides.its_id === undefined ? itsId() : overrides.its_id,
    overrides.name ?? 'Test Member',
    overrides.email ?? `member${++seq}@example.test`,
  ]))!.id;
const createTenant = async (type: 'BUSINESS_UNIT' | 'UTILITY', name: string) =>
  (await one<{ id: string }>(`INSERT INTO ${S}.tenants (tenant_type, name) VALUES ($1, $2) RETURNING id`, [type, name]))!.id;
const createRole = async (level: string, tenantId: string | null, code: string, fullAccess = false) =>
  (await one<{ id: string }>(`INSERT INTO ${S}.roles (role_level, tenant_id, role_code, name, is_full_access) VALUES ($1, $2, $3, $3, $4) RETURNING id`, [
    level,
    tenantId,
    code,
    fullAccess,
  ]))!.id;
const moduleAction = async (module: string, action: string) =>
  (await one<{ id: string }>(
    `SELECT ma.id FROM ${S}.module_actions ma JOIN ${S}.modules m ON m.id = ma.module_id JOIN ${S}.permission_actions a ON a.id = ma.action_id WHERE m.code = $1 AND a.code = $2`,
    [module, action],
  ))?.id;

/** One signed-in session. Defaults describe an ITS (federation) session; pass core_sid: null for a local Non-ITS one. */
let tokenSeq = 0;
const createSession = async (userId: string, roleId: string, overrides: Record<string, unknown> = {}) =>
  (await one<{ id: string }>(
    `INSERT INTO ${S}.user_sessions (user_id, role_id, core_sid, aud, session_token, ip_address, user_agent, expires_at, revoked_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
    [
      userId,
      roleId,
      overrides.core_sid === undefined ? `sid_core_${++tokenSeq}` : overrides.core_sid,
      overrides.aud === undefined ? (overrides.core_sid === null ? null : 'core-admin-web-prod') : overrides.aud,
      overrides.session_token ?? `session_token_${++tokenSeq}`,
      overrides.ip_address ?? '203.0.113.10',
      overrides.user_agent ?? 'Mozilla/5.0 (test)',
      overrides.expires_at ?? new Date(Date.now() + 3600_000).toISOString(),
      overrides.revoked_at ?? null,
    ],
  ))!.id;
const liveSessions = async (userId: string) =>
  (await one<{ n: string }>(`SELECT count(*) n FROM ${S}.user_sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()`, [userId]))!.n;

beforeAll(async () => {
  db = new DataSource(buildDataSourceOptions(loadEnv()));
  await db.initialize();
  await db.runMigrations();
  await db.query(`DELETE FROM ${S}.login_otp_codes`);
  await db.query(`DELETE FROM ${S}.user_sessions`);
  await db.query(`DELETE FROM ${S}.user_roles`);
  await db.query(`DELETE FROM ${S}.role_permissions WHERE role_id IN (SELECT id FROM ${S}.roles WHERE role_code <> $1)`, [PLATFORM_ROLE]);
  await db.query(`DELETE FROM ${S}.roles WHERE role_code <> $1`, [PLATFORM_ROLE]);
  await db.query(`DELETE FROM ${S}.tenants`);
  await db.query(`DELETE FROM ${S}.platform_settings`);
  await db.query(`DELETE FROM ${S}.users`);
});

afterAll(async () => {
  await db?.destroy();
});

describe('miqaat_core schema', () => {
  it('exists next to the unchanged public schema, with the login tables of file 3', async () => {
    const tables = (await rows<{ table_name: string }>(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 ORDER BY 1`, [S])).map((r) => r.table_name);
    expect([...tables].sort()).toEqual(
      [
        'login_otp_codes', 'module_actions', 'modules', 'permission_actions', 'platform_settings', 'role_permissions', 'roles',
        'tenant_core_credentials', 'tenant_domain_credentials', 'tenant_domains', 'tenant_rate_limits', 'tenants', 'user_roles',
        'user_sessions', 'users',
      ].sort(),
    );
    const publicTenants = (await rows<{ column_name: string }>(`SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'tenants'`)).map((r) => r.column_name);
    expect(publicTenants).toContain('tenant_id');
    expect(publicTenants).not.toContain('tenant_type');
  });

  it('creates the enums in flow order, so onboarding stages compare directly', async () => {
    const values = async (type: string) => (await rows<{ v: string }>(`SELECT unnest(enum_range(NULL::${S}.${type}))::text AS v`)).map((r) => r.v);
    expect(await values('onboarding_stage')).toEqual(['WELCOME', 'VERIFY_DETAILS', 'PROVIDE_KEY', 'VERIFY_CONNECTION', 'COMPLETED']);
    expect(await values('role_level')).toEqual(['CORE_ADMIN', 'BUSINESS_UNIT_ADMIN', 'UTILITY_ADMIN']);
    expect(await values('user_status')).toEqual(['INVITED', 'ACTIVE', 'DISABLED']);
    expect((await one<{ ok: boolean }>(`SELECT 'PROVIDE_KEY'::${S}.onboarding_stage >= 'VERIFY_DETAILS' AS ok`))!.ok).toBe(true);
  });

  it('stores no password, assertion or token material for sign-in', async () => {
    const suspicious = await rows<{ table_name: string; column_name: string }>(
      `SELECT table_name, column_name FROM information_schema.columns
        WHERE table_schema = $1
          AND (column_name ILIKE '%password%' OR column_name ILIKE '%pwd%' OR column_name ILIKE '%assertion%'
               OR (table_name = 'login_otp_codes' AND column_name = 'code'))`,
      [S],
    );
    expect(suspicious).toEqual([]);
    const otpColumns = (await rows<{ column_name: string }>(`SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'login_otp_codes'`, [S])).map((r) => r.column_name);
    expect(otpColumns).toContain('code_hash');
    expect(otpColumns).not.toContain('code');
  });
});

describe('reference data: modules and the permission matrix', () => {
  it('seeds the Role-wise Module Access table', async () => {
    const modules = await rows<{ code: string; applies_to_core: boolean; applies_to_tenant: boolean }>(`SELECT code, applies_to_core, applies_to_tenant FROM ${S}.modules ORDER BY display_order`);
    expect(modules.map((m) => m.code)).toEqual(['ROLE', 'USR', 'BUM', 'UTM', 'CFG', 'MUM', 'DCE', 'MON', 'AUD', 'TKT']);
    expect(modules.filter((m) => !m.applies_to_tenant).map((m) => m.code)).toEqual(['BUM', 'UTM', 'MUM']);
    expect(modules.every((m) => m.applies_to_core)).toBe(true);
    expect((await rows(`SELECT code FROM ${S}.permission_actions`)).length).toBe(4);
  });

  it('offers CREATE/READ/UPDATE per module except Configuration CREATE, and APPROVE only on DCE for tenant roles', async () => {
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.module_actions`))!.n).toBe('30');
    expect(await moduleAction('CFG', 'CREATE')).toBeUndefined();
    expect(await moduleAction('CFG', 'READ')).toBeDefined();
    const approve = await one<{ applies_to_core: boolean; applies_to_tenant: boolean }>(
      `SELECT ma.applies_to_core, ma.applies_to_tenant FROM ${S}.module_actions ma JOIN ${S}.permission_actions a ON a.id = ma.action_id JOIN ${S}.modules m ON m.id = ma.module_id WHERE a.code = 'APPROVE'`,
    );
    expect(approve).toEqual({ applies_to_core: false, applies_to_tenant: true });
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.module_actions ma JOIN ${S}.permission_actions a ON a.id = ma.action_id WHERE a.code = 'APPROVE'`))!.n).toBe('1');
  });

  it('seeds the single locked Platform Administrator role with every Core-level checkbox', async () => {
    const role = await one<{ id: string; role_level: string; tenant_id: string | null; is_full_access: boolean; created_by_core_admin: boolean }>(
      `SELECT id, role_level, tenant_id, is_full_access, created_by_core_admin FROM ${S}.roles WHERE role_code = $1`,
      [PLATFORM_ROLE],
    );
    expect(role).toMatchObject({ role_level: 'CORE_ADMIN', tenant_id: null, is_full_access: true, created_by_core_admin: true });
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.role_permissions WHERE role_id = $1`, [role!.id]))!.n).toBe('29');
    expect(await errorCode(`INSERT INTO ${S}.roles (role_level, role_code, name, is_full_access) VALUES ('CORE_ADMIN', 'role-second-platform-admin', 'x', true)`)).toBe('23505');
  });
});

describe('tenants, domains, credentials, settings', () => {
  it('names are unique per tenant type, case-insensitive and trimmed', async () => {
    await createTenant('BUSINESS_UNIT', 'Hall Services');
    expect(await errorCode(`INSERT INTO ${S}.tenants (tenant_type, name) VALUES ('BUSINESS_UNIT', '  hall SERVICES ')`)).toBe('23505');
    await expect(createTenant('UTILITY', 'Hall Services')).resolves.toEqual(expect.any(String));
    expect(await errorCode(`INSERT INTO ${S}.tenants (tenant_type, name) VALUES ('UTILITY', '   ')`)).toBe('23514');
    const t = await one<{ status: string; onboarding_stage: string }>(`SELECT status, onboarding_stage FROM ${S}.tenants WHERE tenant_type = 'UTILITY' AND name = 'Hall Services'`);
    expect(t).toEqual({ status: 'ACTIVE', onboarding_stage: 'WELCOME' });
  });

  it('keeps updated_at current on update', async () => {
    const id = await createTenant('BUSINESS_UNIT', 'Timestamp Check');
    await db.query(`UPDATE ${S}.tenants SET updated_at = now() - interval '1 day' WHERE id = $1`, [id]);
    await db.query(`UPDATE ${S}.tenants SET description = 'changed' WHERE id = $1`, [id]);
    const row = await one<{ fresh: boolean }>(`SELECT updated_at > now() - interval '1 minute' AS fresh FROM ${S}.tenants WHERE id = $1`, [id]);
    expect(row!.fresh).toBe(true);
  });

  it('one default domain per tenant, CUSTOM needs a header name, credentials one per domain, cascade on delete', async () => {
    const tenant = await createTenant('BUSINESS_UNIT', 'Domain Tenant');
    const domain = (await one<{ id: string }>(`INSERT INTO ${S}.tenant_domains (tenant_id, url, is_default, label) VALUES ($1, 'https://api.example.test', true, 'Production') RETURNING id`, [tenant]))!.id;
    expect(await errorCode(`INSERT INTO ${S}.tenant_domains (tenant_id, url, is_default) VALUES ($1, 'https://dev.example.test', true)`, [tenant])).toBe('23505');
    await db.query(`INSERT INTO ${S}.tenant_domains (tenant_id, url, is_default) VALUES ($1, 'https://dev.example.test', false)`, [tenant]);
    expect(await errorCode(`INSERT INTO ${S}.tenant_domains (tenant_id, url, auth_header_type) VALUES ($1, 'https://x.example.test', 'CUSTOM')`, [tenant])).toBe('23514');
    await db.query(`INSERT INTO ${S}.tenant_domains (tenant_id, url, auth_header_type, custom_header_name) VALUES ($1, 'https://y.example.test', 'CUSTOM', 'X-Tenant-Key')`, [tenant]);

    await db.query(`INSERT INTO ${S}.tenant_domain_credentials (tenant_domain_id, access_token_value) VALUES ($1, 'enc:secret')`, [domain]);
    expect(await errorCode(`INSERT INTO ${S}.tenant_domain_credentials (tenant_domain_id, access_token_value) VALUES ($1, 'enc:other')`, [domain])).toBe('23505');

    await db.query(`DELETE FROM ${S}.tenants WHERE id = $1`, [tenant]);
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.tenant_domain_credentials WHERE tenant_domain_id = $1`, [domain]))!.n).toBe('0');
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.tenant_domains WHERE tenant_id = $1`, [tenant]))!.n).toBe('0');
  });

  it('core credentials and rate limits: one per tenant, quota fields required when enabled, SLA ceiling 28 s', async () => {
    const tenant = await createTenant('UTILITY', 'Credential Tenant');
    const insertCreds = `INSERT INTO ${S}.tenant_core_credentials (tenant_id, core_access_token, security_access_key, security_secret_key, standard_queue_arn, fifo_queue_arn, relay_hmac_secret)
                         VALUES ($1, 'enc:t', 'enc:ak', 'enc:sk', 'arn:std', 'arn:fifo', 'enc:hmac')`;
    await db.query(insertCreds, [tenant]);
    expect(await errorCode(insertCreds, [tenant])).toBe('23505');

    const insertLimits = (extra: string, values: string) => `INSERT INTO ${S}.tenant_rate_limits (tenant_id, rate_limit_per_second, burst_limit${extra}) VALUES ($1, 50, 100${values})`;
    expect(await errorCode(insertLimits(', quota_enabled', ', true'), [tenant])).toBe('23514');
    expect(await errorCode(insertLimits(', max_sla_timeout_seconds', ', 29'), [tenant])).toBe('23514');
    await db.query(insertLimits(', quota_enabled, quota_requests, quota_period, max_sla_timeout_seconds', `, true, 10000, 'PER_DAY', 20`), [tenant]);
    expect(await errorCode(insertLimits('', ''), [tenant])).toBe('23505');
  });

  it('platform_settings is a singleton with valid SLA and quota values', async () => {
    const insert = (id: number, defaultSla: number, maxSla: number, quota = '') =>
      `INSERT INTO ${S}.platform_settings (id, event_bus_name, event_bus_arn, core_rate_limit_per_second, core_rate_limit_burst, default_sla_timeout_seconds, max_sla_timeout_seconds${quota ? ', core_quota_enabled' : ''})
       VALUES (${id}, 'miqaat-core-bus', 'arn:aws:events:ap-south-1:000000000000:event-bus/miqaat-core-bus', 100, 200, ${defaultSla}, ${maxSla}${quota ? ', true' : ''})`;
    expect(await errorCode(insert(2, 10, 28))).toBe('23514');
    expect(await errorCode(insert(1, 10, 29))).toBe('23514');
    expect(await errorCode(insert(1, 20, 10))).toBe('23514');
    expect(await errorCode(insert(1, 10, 28, 'quota'))).toBe('23514');
    await db.query(insert(1, 10, 28));
    expect(await errorCode(insert(1, 10, 28))).toBe('23505');
    const row = await one<{ timezone: string; its_sync_frequency_unit: string; max_admins_per_tenant: number }>(`SELECT timezone, its_sync_frequency_unit, max_admins_per_tenant FROM ${S}.platform_settings`);
    expect(row).toEqual({ timezone: 'UTC', its_sync_frequency_unit: 'HOURS', max_admins_per_tenant: 1 });
  });
});

describe('roles and the permission matrix', () => {
  it('tenant_id is empty exactly for CORE_ADMIN roles, and the level matches the tenant type', async () => {
    const bu = await createTenant('BUSINESS_UNIT', 'Role Tenant BU');
    const util = await createTenant('UTILITY', 'Role Tenant UT');
    expect(await errorCode(`INSERT INTO ${S}.roles (role_level, tenant_id, role_code, name) VALUES ('CORE_ADMIN', $1, 'role-core-with-tenant', 'x')`, [bu])).toBe('23514');
    expect(await errorCode(`INSERT INTO ${S}.roles (role_level, role_code, name) VALUES ('BUSINESS_UNIT_ADMIN', 'role-bu-without-tenant', 'x')`)).toBe('23514');
    expect(await errorCode(`INSERT INTO ${S}.roles (role_level, tenant_id, role_code, name) VALUES ('UTILITY_ADMIN', $1, 'role-utility-on-bu', 'x')`, [bu])).toBe('23514');
    await expect(createRole('UTILITY_ADMIN', util, 'role-utility-admin-ok')).resolves.toEqual(expect.any(String));
    expect(await errorCode(`INSERT INTO ${S}.roles (role_level, role_code, name) VALUES ('CORE_ADMIN', 'Role Bad Code', 'x')`)).toBe('23514');
  });

  it('one full-access role per tenant; created_by_core_admin is generated and read-only', async () => {
    const bu = await createTenant('BUSINESS_UNIT', 'Full Access Tenant');
    const admin = await createRole('BUSINESS_UNIT_ADMIN', bu, 'role-fat-business-unit-admin', true);
    const sub = await createRole('BUSINESS_UNIT_ADMIN', bu, 'role-fat-zone-manager');
    expect(await errorCode(`INSERT INTO ${S}.roles (role_level, tenant_id, role_code, name, is_full_access) VALUES ('BUSINESS_UNIT_ADMIN', $1, 'role-fat-second-admin', 'x', true)`, [bu])).toBe('23505');
    const flags = await rows<{ id: string; created_by_core_admin: boolean }>(`SELECT id, created_by_core_admin FROM ${S}.roles WHERE id = ANY($1)`, [[admin, sub]]);
    expect(flags.find((r) => r.id === admin)!.created_by_core_admin).toBe(true);
    expect(flags.find((r) => r.id === sub)!.created_by_core_admin).toBe(false);
    expect(await errorCode(`UPDATE ${S}.roles SET created_by_core_admin = true WHERE id = $1`, [sub])).toBe('428C9');
    expect(await errorCode(`INSERT INTO ${S}.roles (role_level, tenant_id, role_code, name) VALUES ('BUSINESS_UNIT_ADMIN', $1, 'role-fat-zone-manager', 'dup')`, [bu])).toBe('23505');
  });

  it('grants only checkboxes the matrix offers for the role level', async () => {
    const bu = await createTenant('BUSINESS_UNIT', 'Matrix Tenant');
    const buRole = await createRole('BUSINESS_UNIT_ADMIN', bu, 'role-matrix-bu');
    const platform = (await one<{ id: string }>(`SELECT id FROM ${S}.roles WHERE role_code = $1`, [PLATFORM_ROLE]))!.id;
    const grant = (role: string, ma: string | undefined) => errorCode(`INSERT INTO ${S}.role_permissions (role_id, module_action_id) VALUES ($1, $2)`, [role, ma]);

    expect(await grant(buRole, await moduleAction('DCE', 'APPROVE'))).toBe('NO_ERROR');
    expect(await grant(platform, await moduleAction('DCE', 'APPROVE'))).toBe('23514');
    expect(await grant(buRole, await moduleAction('BUM', 'READ'))).toBe('23514');
    expect(await grant(buRole, await moduleAction('USR', 'CREATE'))).toBe('NO_ERROR');
    expect(await grant(buRole, await moduleAction('USR', 'CREATE'))).toBe('23505');
    expect(await errorCode(`DELETE FROM ${S}.module_actions WHERE id = $1`, [await moduleAction('USR', 'CREATE')])).toBe('23503');
  });
});

describe('users and role assignment', () => {
  it('accepts ITS members and Non-ITS members: 8 digits when present, unique email, Active implies has_been_active', async () => {
    expect(await errorCode(`INSERT INTO ${S}.users (its_id, name, email) VALUES ('1234567', 'x', 'short@example.test')`)).toBe('23514');
    expect(await errorCode(`INSERT INTO ${S}.users (its_id, name, email) VALUES ('ITS12345', 'x', 'letters@example.test')`)).toBe('23514');
    const id = await createUser({ email: 'unique@example.test' });
    expect(await errorCode(`INSERT INTO ${S}.users (its_id, name, email) VALUES ($1, 'x', 'unique@example.test')`, [itsId()])).toBe('23505');
    expect((await one<{ status: string }>(`SELECT status FROM ${S}.users WHERE id = $1`, [id]))!.status).toBe('INVITED');
    expect(await errorCode(`UPDATE ${S}.users SET status = 'ACTIVE' WHERE id = $1`, [id])).toBe('23514');
    await db.query(`UPDATE ${S}.users SET status = 'ACTIVE', has_been_active = true, last_login_at = now() WHERE id = $1`, [id]);
  });

  it('Non-ITS members have no ITS ID, and several may exist side by side', async () => {
    const first = await createUser({ its_id: null, email: 'nonits1@example.test' });
    const second = await createUser({ its_id: null, email: 'nonits2@example.test' });
    expect((await one<{ its_id: string | null }>(`SELECT its_id FROM ${S}.users WHERE id = $1`, [first]))!.its_id).toBeNull();
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.users WHERE id = ANY($1) AND its_id IS NULL`, [[first, second]]))!.n).toBe('2');
    // the ITS ID stays unique for the members that do have one
    const its = itsId();
    await createUser({ its_id: its, email: 'itsunique@example.test' });
    expect(await errorCode(`INSERT INTO ${S}.users (its_id, name, email) VALUES ($1, 'dup', 'itsdup@example.test')`, [its])).toBe('23505');
  });

  it('copies tenant and level from the role, one role per tenant, one Core Admin role, roles across tenants allowed', async () => {
    const admin = await createUser();
    const member = await createUser();
    const buA = await createTenant('BUSINESS_UNIT', 'Assign BU A');
    const buB = await createTenant('BUSINESS_UNIT', 'Assign BU B');
    const roleA1 = await createRole('BUSINESS_UNIT_ADMIN', buA, 'role-assign-a1');
    const roleA2 = await createRole('BUSINESS_UNIT_ADMIN', buA, 'role-assign-a2');
    const roleB = await createRole('BUSINESS_UNIT_ADMIN', buB, 'role-assign-b');
    const coreRole = await createRole('CORE_ADMIN', null, 'role-assign-core-viewer');
    const platform = (await one<{ id: string }>(`SELECT id FROM ${S}.roles WHERE role_code = $1`, [PLATFORM_ROLE]))!.id;
    const assign = (role: string) => errorCode(`INSERT INTO ${S}.user_roles (user_id, role_id, assigned_by) VALUES ($1, $2, $3)`, [member, role, admin]);

    expect(await assign(roleA1)).toBe('NO_ERROR');
    const copied = await one<{ tenant_id: string; role_level: string }>(`SELECT tenant_id, role_level FROM ${S}.user_roles WHERE user_id = $1 AND role_id = $2`, [member, roleA1]);
    expect(copied).toEqual({ tenant_id: buA, role_level: 'BUSINESS_UNIT_ADMIN' });
    expect(await errorCode(`INSERT INTO ${S}.user_roles (user_id, role_id, tenant_id, role_level) VALUES ($1, $2, $3, 'CORE_ADMIN')`, [member, roleB, buA])).toBe('NO_ERROR');
    expect((await one<{ tenant_id: string; role_level: string }>(`SELECT tenant_id, role_level FROM ${S}.user_roles WHERE user_id = $1 AND role_id = $2`, [member, roleB]))).toEqual({ tenant_id: buB, role_level: 'BUSINESS_UNIT_ADMIN' });

    expect(await assign(roleA2)).toBe('23505');
    expect(await assign(roleA1)).toBe('23505');
    expect(await assign(platform)).toBe('NO_ERROR');
    expect(await assign(coreRole)).toBe('23505');

    await db.query(`DELETE FROM ${S}.roles WHERE id = $1`, [roleB]);
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.user_roles WHERE user_id = $1`, [member]))!.n).toBe('2');
    await db.query(`DELETE FROM ${S}.users WHERE id = $1`, [admin]);
    expect((await one<{ assigned_by: string | null }>(`SELECT assigned_by FROM ${S}.user_roles WHERE user_id = $1 AND role_id = $2`, [member, roleA1]))!.assigned_by).toBeNull();
  });
});

describe('local sessions (user_sessions)', () => {
  it('records an ITS federation session with core_sid and aud, and a local Non-ITS session with neither', async () => {
    const tenant = await createTenant('BUSINESS_UNIT', 'Session Tenant');
    const role = await createRole('BUSINESS_UNIT_ADMIN', tenant, 'role-session-admin');
    const itsMember = await createUser({ email: 'session.its@example.test' });
    const nonIts = await createUser({ its_id: null, email: 'session.local@example.test' });

    const federated = await createSession(itsMember, role, { core_sid: 'sid_core_abc', aud: 'core-admin-web-prod' });
    const local = await createSession(nonIts, role, { core_sid: null });

    const rowFederated = await one<{ core_sid: string | null; aud: string | null; role_id: string; revoked_at: string | null }>(
      `SELECT core_sid, aud, role_id, revoked_at FROM ${S}.user_sessions WHERE id = $1`,
      [federated],
    );
    expect(rowFederated).toEqual({ core_sid: 'sid_core_abc', aud: 'core-admin-web-prod', role_id: role, revoked_at: null });
    const rowLocal = await one<{ core_sid: string | null; aud: string | null }>(`SELECT core_sid, aud FROM ${S}.user_sessions WHERE id = $1`, [local]);
    expect(rowLocal).toEqual({ core_sid: null, aud: null });
    expect(await liveSessions(itsMember)).toBe('1');
  });

  it('keeps session_token unique but allows several local sessions for one federation sid', async () => {
    const tenant = await createTenant('UTILITY', 'Session Tenant Two');
    const role = await createRole('UTILITY_ADMIN', tenant, 'role-session-utility');
    const user = await createUser({ email: 'session.tabs@example.test' });

    await createSession(user, role, { core_sid: 'sid_two_tabs', session_token: 'token_tab_one' });
    await createSession(user, role, { core_sid: 'sid_two_tabs', session_token: 'token_tab_two' });
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.user_sessions WHERE core_sid = 'sid_two_tabs'`))!.n).toBe('2');
    expect(
      await errorCode(
        `INSERT INTO ${S}.user_sessions (user_id, role_id, session_token, expires_at) VALUES ($1, $2, 'token_tab_one', now() + interval '1 hour')`,
        [user, role],
      ),
    ).toBe('23505');
  });

  it('counts a session as live only while it is neither expired nor revoked', async () => {
    const tenant = await createTenant('BUSINESS_UNIT', 'Session Lifecycle');
    const role = await createRole('BUSINESS_UNIT_ADMIN', tenant, 'role-session-lifecycle');
    const user = await createUser({ email: 'session.lifecycle@example.test' });

    const live = await createSession(user, role, { session_token: 'token_live' });
    const expired = await createSession(user, role, { session_token: 'token_expired' });
    // A session expires by time passing: both timestamps move back, so expires_at stays after created_at.
    await db.query(`UPDATE ${S}.user_sessions SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1`, [expired]);
    const revoked = await createSession(user, role, { session_token: 'token_revoked', revoked_at: new Date().toISOString() });
    expect(await liveSessions(user)).toBe('1');

    await db.query(`UPDATE ${S}.user_sessions SET revoked_at = now() WHERE id = $1`, [live]);
    expect(await liveSessions(user)).toBe('0');
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.user_sessions WHERE id = ANY($1)`, [[live, expired, revoked]]))!.n).toBe('3');
  });

  it('back-channel logout revokes every live session of one federation sid, and leaves other sids alone', async () => {
    const tenant = await createTenant('BUSINESS_UNIT', 'Session Backchannel');
    const role = await createRole('BUSINESS_UNIT_ADMIN', tenant, 'role-session-backchannel');
    const user = await createUser({ email: 'session.backchannel@example.test' });

    await createSession(user, role, { core_sid: 'sid_logout_me', session_token: 'token_bc_one' });
    await createSession(user, role, { core_sid: 'sid_logout_me', session_token: 'token_bc_two' });
    await createSession(user, role, { core_sid: 'sid_keep_me', session_token: 'token_bc_three' });

    await db.query(`UPDATE ${S}.user_sessions SET revoked_at = now() WHERE core_sid = $1 AND revoked_at IS NULL`, ['sid_logout_me']);
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.user_sessions WHERE core_sid = 'sid_logout_me' AND revoked_at IS NULL`))!.n).toBe('0');
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.user_sessions WHERE core_sid = 'sid_keep_me' AND revoked_at IS NULL`))!.n).toBe('1');
  });

  it('rejects an impossible lifetime or a half-federated session, and disappears with its user or role', async () => {
    const tenant = await createTenant('BUSINESS_UNIT', 'Session Constraints');
    const role = await createRole('BUSINESS_UNIT_ADMIN', tenant, 'role-session-constraints');
    const user = await createUser({ email: 'session.constraints@example.test' });

    expect(
      await errorCode(`INSERT INTO ${S}.user_sessions (user_id, role_id, session_token, expires_at) VALUES ($1, $2, 'token_past', now() - interval '1 minute')`, [user, role]),
    ).toBe('23514');
    expect(
      await errorCode(
        `INSERT INTO ${S}.user_sessions (user_id, role_id, aud, session_token, expires_at) VALUES ($1, $2, 'core-admin-web-prod', 'token_aud_only', now() + interval '1 hour')`,
        [user, role],
      ),
    ).toBe('23514');
    expect(
      await errorCode(`INSERT INTO ${S}.user_sessions (user_id, role_id, session_token, expires_at) VALUES ($1, gen_random_uuid(), 'token_no_role', now() + interval '1 hour')`, [user]),
    ).toBe('23503');

    await createSession(user, role, { session_token: 'token_cascade_user' });
    await db.query(`DELETE FROM ${S}.users WHERE id = $1`, [user]);
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.user_sessions WHERE user_id = $1`, [user]))!.n).toBe('0');

    const other = await createUser({ email: 'session.cascade.role@example.test' });
    await createSession(other, role, { session_token: 'token_cascade_role' });
    await db.query(`DELETE FROM ${S}.roles WHERE id = $1`, [role]);
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.user_sessions WHERE role_id = $1`, [role]))!.n).toBe('0');
  });
});

describe('Non-ITS one-time codes (login_otp_codes)', () => {
  const insertCode = (userId: string, hash = 'hash:123456', expires = `now() + interval '10 minutes'`) =>
    `INSERT INTO ${S}.login_otp_codes (user_id, code_hash, expires_at) VALUES ('${userId}', '${hash}', ${expires})`;

  it('stores only a hash, starts unconsumed with zero attempts, and counts wrong tries', async () => {
    const user = await createUser({ its_id: null, email: 'otp.member@example.test' });
    await db.query(insertCode(user));
    const code = await one<{ id: string; code_hash: string; consumed_at: string | null; attempt_count: number }>(
      `SELECT id, code_hash, consumed_at, attempt_count FROM ${S}.login_otp_codes WHERE user_id = $1`,
      [user],
    );
    expect(code).toMatchObject({ code_hash: 'hash:123456', consumed_at: null, attempt_count: 0 });

    await db.query(`UPDATE ${S}.login_otp_codes SET attempt_count = attempt_count + 1 WHERE id = $1`, [code!.id]);
    expect((await one<{ attempt_count: number }>(`SELECT attempt_count FROM ${S}.login_otp_codes WHERE id = $1`, [code!.id]))!.attempt_count).toBe(1);
    expect(await errorCode(`UPDATE ${S}.login_otp_codes SET attempt_count = -1 WHERE id = $1`, [code!.id])).toBe('23514');

    await db.query(`UPDATE ${S}.login_otp_codes SET consumed_at = now() WHERE id = $1`, [code!.id]);
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.login_otp_codes WHERE user_id = $1 AND consumed_at IS NULL AND expires_at > now()`, [user]))!.n).toBe('0');
  });

  it('allows a resent code next to the previous one and rejects an already expired code', async () => {
    const user = await createUser({ its_id: null, email: 'otp.resend@example.test' });
    await db.query(insertCode(user, 'hash:first'));
    await db.query(insertCode(user, 'hash:second'));
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.login_otp_codes WHERE user_id = $1 AND consumed_at IS NULL`, [user]))!.n).toBe('2');
    expect(await errorCode(insertCode(user, 'hash:past', `now() - interval '1 minute'`))).toBe('23514');
  });

  it('disappears with its user', async () => {
    const user = await createUser({ its_id: null, email: 'otp.cascade@example.test' });
    await db.query(insertCode(user));
    await db.query(`DELETE FROM ${S}.users WHERE id = $1`, [user]);
    expect((await one<{ n: string }>(`SELECT count(*) n FROM ${S}.login_otp_codes WHERE user_id = $1`, [user]))!.n).toBe('0');
  });
});
