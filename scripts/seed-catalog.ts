/**
 * Idempotent seed of the Authorization DB:
 *  - Core RBAC: tenant, 14 default modules + permissions, 5 system roles with the permissions matrix
 *  - organisation: business units, utilities
 *  - federation: environments, applications, application modules + custom roles, clients, service principals
 *
 * Everything is ordinary data that can equally be managed through the admin APIs.
 *   npm run seed
 */
import 'reflect-metadata';
import Redis from 'ioredis';
import { loadEnv } from '@config/configuration';
import { PermissionAction, permissionCode, ScopeLevel } from '@common/constants/rbac.constants';
import { normalizeOrigin, normalizeRedirectUri } from '@common/utils/uri-policy';
import dataSource from '@core/database/data-source';
import { seedCoreRbac } from '@modules/rbac/seed/core-rbac.seed';

const ENVIRONMENTS = [
  { code: 'DEV', name: 'Development', is_production: false, sort_order: 0 },
  { code: 'UAT', name: 'User Acceptance Testing', is_production: false, sort_order: 1 },
  { code: 'PROD', name: 'Production', is_production: true, sort_order: 2 },
];

const BUSINESS_UNITS = ['RMS', 'VMS', 'Mumin Services', 'Core Services'];

const UTILITIES: { name: string; bu: string }[] = [
  { name: 'Helpdesk', bu: 'RMS' },
  { name: 'Zone Support', bu: 'RMS' },
  { name: 'AMS', bu: 'Core Services' },
];

interface AppSeed {
  code: string;
  name: string;
  bu?: string;
  utility?: string;
  clientPrefix: string;
  devPort: number;
  hosts: { UAT: string; PROD: string };
  modules: { code: string; name: string; actions: PermissionAction[] }[];
  roles: { name: string; level: ScopeLevel; permissions: string[] | '*' }[];
}

const APPLICATIONS: AppSeed[] = [
  {
    code: 'rms',
    name: 'RMS Web',
    bu: 'RMS',
    clientPrefix: 'rms-web',
    devPort: 4001,
    hosts: { UAT: 'https://rms-uat.example.com', PROD: 'https://rms.example.com' },
    modules: [
      { code: 'RMS_REGISTRATION', name: 'RMS Registration', actions: ['view', 'create', 'edit', 'delete'] },
      { code: 'RMS_REPORTS', name: 'RMS Reports', actions: ['view'] },
    ],
    roles: [
      { name: 'RMS Registration Admin', level: 'BUSINESS_UNIT', permissions: '*' },
      { name: 'RMS Registration Operator', level: 'BUSINESS_UNIT', permissions: ['RMS_REGISTRATION_VIEW', 'RMS_REGISTRATION_CREATE'] },
      { name: 'RMS Viewer', level: 'BUSINESS_UNIT', permissions: ['RMS_REGISTRATION_VIEW', 'RMS_REPORTS_VIEW'] },
    ],
  },
  {
    code: 'ams',
    name: 'AMS Web',
    utility: 'AMS',
    clientPrefix: 'ams-web',
    devPort: 4002,
    hosts: { UAT: 'https://ams-uat.example.com', PROD: 'https://ams.example.com' },
    modules: [{ code: 'AMS_USERS', name: 'AMS Users', actions: ['view', 'create', 'edit'] }],
    roles: [
      { name: 'AMS User Admin', level: 'UTILITY', permissions: '*' },
      { name: 'AMS Viewer', level: 'UTILITY', permissions: ['AMS_USERS_VIEW'] },
    ],
  },
  {
    code: 'vms',
    name: 'VMS Web',
    bu: 'VMS',
    clientPrefix: 'vms-web',
    devPort: 4003,
    hosts: { UAT: 'https://vms-uat.example.com', PROD: 'https://vms.example.com' },
    modules: [{ code: 'VMS_EVENTS', name: 'VMS Events', actions: ['view', 'create', 'edit'] }],
    roles: [
      { name: 'VMS Events Admin', level: 'BUSINESS_UNIT', permissions: '*' },
      { name: 'VMS Viewer', level: 'BUSINESS_UNIT', permissions: ['VMS_EVENTS_VIEW'] },
    ],
  },
  {
    code: 'mumin-web',
    name: 'Mumin Web',
    bu: 'Mumin Services',
    clientPrefix: 'mumin-web',
    devPort: 4004,
    hosts: { UAT: 'https://mumin-uat.example.com', PROD: 'https://mumin.example.com' },
    modules: [{ code: 'MUMIN_PROFILE', name: 'Mumin Profile', actions: ['view', 'edit'] }],
    roles: [{ name: 'Mumin Member', level: 'BUSINESS_UNIT', permissions: '*' }],
  },
  {
    code: 'core-portal',
    name: 'Core Portal',
    clientPrefix: 'core-portal',
    devPort: 4000,
    hosts: { UAT: 'https://core-uat.example.com', PROD: 'https://core.example.com' },
    modules: [],
    roles: [],
  },
];

/** One production client is intentionally left in SECURITY_REVIEW to demonstrate the lifecycle gate. */
const HELD_IN_REVIEW = new Set(['mumin-web-prod']);

async function main() {
  const env = loadEnv();
  await dataSource.initialize();
  const db = dataSource;
  const one = async <T>(sql: string, params: unknown[]) => ((await db.query(sql, params)) as T[])[0];

  const core = await seedCoreRbac(db, env.DEFAULT_TENANT_NAME);
  const tenantId = core.tenantId;

  for (const e of ENVIRONMENTS) {
    await db.query(
      `INSERT INTO environments (code, name, is_production, sort_order) VALUES ($1, $2, $3, $4)
       ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name, is_production = EXCLUDED.is_production, sort_order = EXCLUDED.sort_order`,
      [e.code, e.name, e.is_production, e.sort_order],
    );
  }

  const buIds: Record<string, string> = {};
  for (const name of BUSINESS_UNITS) {
    const bu = await one<{ bu_id: string }>(
      `INSERT INTO business_units (tenant_id, name) VALUES ($1, $2) ON CONFLICT (tenant_id, name) DO UPDATE SET name = EXCLUDED.name RETURNING bu_id`,
      [tenantId, name],
    );
    buIds[name] = bu.bu_id;
  }
  const utilityIds: Record<string, string> = {};
  for (const u of UTILITIES) {
    const row = await one<{ utility_id: string }>(
      `INSERT INTO utilities (bu_id, name) VALUES ($1, $2) ON CONFLICT (bu_id, name) DO UPDATE SET name = EXCLUDED.name RETURNING utility_id`,
      [buIds[u.bu], u.name],
    );
    utilityIds[u.name] = row.utility_id;
  }

  let clientCount = 0;
  for (const app of APPLICATIONS) {
    const appRow = await one<{ application_id: string }>(
      `INSERT INTO applications (tenant_id, bu_id, utility_id, code, name) VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name, bu_id = EXCLUDED.bu_id, utility_id = EXCLUDED.utility_id RETURNING application_id`,
      [tenantId, app.bu ? buIds[app.bu] : null, app.utility ? utilityIds[app.utility] : null, app.code, app.name],
    );

    const appPermissions: string[] = [];
    for (const mod of app.modules) {
      const modRow = await one<{ module_id: string }>(
        `INSERT INTO modules (module_code, module_name, is_default, application_id) VALUES ($1, $2, false, $3)
         ON CONFLICT (module_code) DO UPDATE SET module_name = EXCLUDED.module_name, application_id = EXCLUDED.application_id RETURNING module_id`,
        [mod.code, mod.name, appRow.application_id],
      );
      for (const action of mod.actions) {
        const code = permissionCode(mod.code, action);
        appPermissions.push(code);
        await db.query(`INSERT INTO permissions (module_id, action, permission_code) VALUES ($1, $2, $3) ON CONFLICT (permission_code) DO NOTHING`, [
          modRow.module_id,
          action,
          code,
        ]);
      }
    }

    for (const role of app.roles) {
      const roleRow = await one<{ role_id: string }>(
        `INSERT INTO roles (tenant_id, role_name, scope_level, is_system_role) VALUES ($1, $2, $3, false)
         ON CONFLICT (tenant_id, role_name) DO UPDATE SET scope_level = EXCLUDED.scope_level RETURNING role_id`,
        [tenantId, role.name, role.level],
      );
      await db.query(
        `INSERT INTO role_permissions (role_id, permission_id) SELECT $1, permission_id FROM permissions WHERE permission_code = ANY($2) ON CONFLICT DO NOTHING`,
        [roleRow.role_id, role.permissions === '*' ? appPermissions : role.permissions],
      );
    }

    for (const e of ENVIRONMENTS) {
      if (e.code === 'DEV' && !env.ALLOW_INSECURE_LOCALHOST_URIS) continue;
      const envRow = await one<{ id: string }>(`SELECT id FROM environments WHERE code = $1`, [e.code]);
      const base = e.code === 'DEV' ? `http://localhost:${app.devPort}` : app.hosts[e.code as 'UAT' | 'PROD'];
      const clientId = `${app.clientPrefix}-${e.code.toLowerCase()}`;
      const allow = env.ALLOW_INSECURE_LOCALHOST_URIS;
      const uri = (path: string) => normalizeRedirectUri(`${base}${path}`, allow);
      if (await one(`SELECT 1 FROM clients WHERE client_id = $1`, [clientId])) continue;

      const target = HELD_IN_REVIEW.has(clientId) ? 'SECURITY_REVIEW' : 'ACTIVE';
      const client = await one<{ id: string }>(
        `INSERT INTO clients (client_id, application_id, environment_id, name, client_type, authentication_mode, status, initiate_login_uri)
         VALUES ($1, $2, $3, $4, 'WEB', 'EMBEDDED_OR_REDIRECT', $5, $6) RETURNING id`,
        [clientId, appRow.application_id, envRow.id, `${app.name} (${e.code})`, target, uri('/auth/core/login')],
      );
      await db.query(`INSERT INTO client_origins (client_ref, origin, created_by) VALUES ($1, $2, 'seed')`, [client.id, normalizeOrigin(base, allow)]);
      if (clientId === 'rms-web-dev') {
        // local embedded-login playground (core-authentication: npm run example:playground)
        await db.query(`INSERT INTO client_origins (client_ref, origin, created_by) VALUES ($1, $2, 'seed')`, [client.id, normalizeOrigin('http://localhost:3000', allow)]);
      }
      await db.query(
        `INSERT INTO client_redirect_uris (client_ref, uri, uri_type, is_primary, created_by) VALUES
           ($1, $2, 'CALLBACK', true, 'seed'), ($1, $3, 'BACK_CHANNEL_LOGOUT', true, 'seed'), ($1, $4, 'POST_LOGOUT_REDIRECT', true, 'seed')`,
        [client.id, uri('/auth/core/callback'), uri('/auth/core/logout'), uri('/logout/callback')],
      );
      let from: string | null = null;
      for (const to of target === 'ACTIVE' ? ['PENDING', 'SECURITY_REVIEW', 'ACTIVE'] : ['PENDING', 'SECURITY_REVIEW']) {
        await db.query(`INSERT INTO client_status_history (client_ref, from_status, to_status, reason, changed_by) VALUES ($1, $2, $3, 'seed', 'seed')`, [client.id, from, to]);
        from = to;
      }
      clientCount++;
    }
  }

  // Service principals authenticate with RS256 JWTs verified against their own JWKS (no API keys).
  const principals: { id: string; name: string; jwks: string; scopes: string[]; clients: string[] | null }[] = [
    { id: 'identity-federation', name: 'Miqaat Identity Federation', jwks: env.IDENTITY_JWKS_URI, scopes: ['FEDERATION', 'AUTHZ_CHECK'], clients: ['core-portal-dev', 'core-portal-uat', 'core-portal-prod'] },
    ...(env.ALLOW_INSECURE_LOCALHOST_URIS
      ? [
          { id: 'rms-backend', name: 'RMS Web backend', jwks: 'http://localhost:4001/.well-known/jwks.json', scopes: ['AUTHZ_CHECK'], clients: ['rms-web-dev', 'rms-web-uat', 'rms-web-prod'] },
          { id: 'ams-backend', name: 'AMS Web backend', jwks: 'http://localhost:4002/.well-known/jwks.json', scopes: ['AUTHZ_CHECK'], clients: ['ams-web-dev', 'ams-web-uat', 'ams-web-prod'] },
          { id: 'vms-backend', name: 'VMS Web backend', jwks: 'http://localhost:4003/.well-known/jwks.json', scopes: ['AUTHZ_CHECK'], clients: ['vms-web-dev', 'vms-web-uat', 'vms-web-prod'] },
        ]
      : []),
  ];
  for (const p of principals) {
    await db.query(
      `INSERT INTO service_principals (principal_id, name, jwks_uri, scopes, allowed_client_ids) VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (principal_id) DO UPDATE SET name = EXCLUDED.name, jwks_uri = EXCLUDED.jwks_uri, scopes = EXCLUDED.scopes,
         allowed_client_ids = EXCLUDED.allowed_client_ids, status = 'ACTIVE', revoked_at = NULL`,
      [p.id, p.name, normalizeRedirectUri(p.jwks, env.ALLOW_INSECURE_LOCALHOST_URIS), p.scopes, p.clients],
    );
  }

  const redis = new Redis(env.REDIS_URL);
  await redis.incr('authz:version');
  await redis.quit();

  const counts = await one<Record<string, string>>(
    `SELECT (SELECT count(*) FROM tenants) AS tenants, (SELECT count(*) FROM business_units) AS business_units,
            (SELECT count(*) FROM utilities) AS utilities, (SELECT count(*) FROM modules WHERE is_default) AS default_modules,
            (SELECT count(*) FROM modules WHERE NOT is_default) AS app_modules, (SELECT count(*) FROM permissions) AS permissions,
            (SELECT count(*) FROM roles WHERE is_system_role) AS system_roles, (SELECT count(*) FROM roles WHERE NOT is_system_role) AS custom_roles,
            (SELECT count(*) FROM applications) AS applications, (SELECT count(*) FROM clients) AS clients,
            (SELECT count(*) FROM service_principals) AS service_principals`,
    [],
  );
  console.log(`catalog seeded (new clients this run: ${clientCount})`, counts);
  await dataSource.destroy();
}

main().catch(async (error: unknown) => {
  console.error('seed failed:', error instanceof Error ? error.message : error);
  await dataSource.destroy().catch(() => undefined);
  process.exit(1);
});
