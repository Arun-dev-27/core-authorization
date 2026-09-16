/**
 * Integration tests against real PostgreSQL + Redis:
 *  - MIQAAT CORE Role & Permission Module: schema, 14 default modules, 5 system roles, permission matrix
 *  - workspaces: multi-assignment users, active scope in the token, GET /me/permissions
 *  - scope enforcement: sub-role creation, assignment scopes, privilege escalation, system roles
 *  - JWKS bearer authentication (service principals + administrator tokens, no API keys)
 *  - login federation: applications, clients, authorization checks for BU applications
 * Run: npm run infra:up && npm run test:e2e
 */
import { randomUUID } from 'node:crypto';
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import Redis from 'ioredis';
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, KeyLike, SignJWT } from 'jose';
import { DataSource } from 'typeorm';
import { loadEnv } from '@config/configuration';
import { buildDataSourceOptions } from '@core/database/data-source-options';
import { seedCoreRbac } from '@modules/rbac/seed/core-rbac.seed';
import { createApp } from '../src/bootstrap';

type Method = 'GET' | 'POST' | 'PATCH' | 'DELETE';
type SignerName = 'identity' | 'federation' | 'rms' | 'automation' | 'rogue';
type ScopeType = 'CORE' | 'BUSINESS_UNIT' | 'UTILITY';
interface Signer {
  kid: string;
  privateKey: KeyLike;
  jwk: Record<string, unknown>;
}

const AUDIENCE = 'miqaat-core-authorization';
const IDENTITY_ISSUER = 'https://identity.miqaat.test';
const TENANT = 'Miqaat Test';
const DEMO = { core: '30416234', buAdmin: '31189012', buSub: '31145678', utilAdmin: '31267890', utilSub: '31278901' };

/** Section 4 of the design document, written independently of the seed data. */
const EXPECTED: Record<string, Record<string, string[]>> = {
  'Platform Administrator': {
    DASHBOARD: ['view'],
    BUSINESS_UNIT_MGMT: ['view', 'create', 'edit'],
    UTILITY_MGMT: ['view', 'create', 'edit'],
    ROLE_MGMT: ['view', 'create', 'edit'],
    USER_MGMT: ['view', 'create', 'edit'],
    MUMIN_INFO: ['view'],
    EVENT_CONTRACT: ['view', 'create', 'edit', 'approve'],
    API_CONTRACT: ['view', 'create', 'edit', 'approve'],
    ACCESS_REQUEST: ['view', 'create', 'edit', 'approve'],
    TICKET_MGMT: ['view', 'create', 'edit'],
    MONITORING: ['view'],
    AUDIT_LOG: ['view'],
    CONFIGURATION: ['view', 'edit'],
  },
  // exactly the GET /me/permissions example of section 6
  'Business Unit Admin': {
    DASHBOARD: ['view'],
    ROLE_MGMT: ['view', 'create', 'edit'],
    USER_MGMT: ['view', 'create', 'edit'],
    EVENT_CONTRACT: ['view', 'create', 'approve'],
    API_CONTRACT: ['view', 'create', 'approve'],
    CONTRACT_LIBRARY: ['view'],
    ACCESS_REQUEST: ['view', 'create', 'approve'],
    TICKET_MGMT: ['view', 'create', 'edit'],
    MONITORING: ['view'],
    AUDIT_LOG: ['view'],
    CONFIGURATION: ['view', 'edit'],
  },
  'BU Sub-Level Admin': {
    DASHBOARD: ['view'],
    USER_MGMT: ['view', 'edit'],
    EVENT_CONTRACT: ['view', 'create'],
    API_CONTRACT: ['view', 'create'],
    CONTRACT_LIBRARY: ['view'],
    ACCESS_REQUEST: ['view', 'create'],
    TICKET_MGMT: ['view', 'create'],
    MONITORING: ['view'],
  },
  'Utility Admin': {
    DASHBOARD: ['view'],
    ROLE_MGMT: ['view', 'create', 'edit'],
    USER_MGMT: ['view', 'create', 'edit'],
    EVENT_CONTRACT: ['view', 'create', 'approve'],
    API_CONTRACT: ['view', 'create', 'approve'],
    CONTRACT_LIBRARY: ['view'],
    ACCESS_REQUEST: ['view', 'create', 'approve'],
    TICKET_MGMT: ['view', 'create', 'edit'],
    MONITORING: ['view'],
    AUDIT_LOG: ['view'],
    CONFIGURATION: ['view', 'edit'],
  },
  'Utility Sub-Level Admin': {
    DASHBOARD: ['view'],
    USER_MGMT: ['view', 'edit'],
    EVENT_CONTRACT: ['view', 'create'],
    API_CONTRACT: ['view', 'create'],
    CONTRACT_LIBRARY: ['view'],
    ACCESS_REQUEST: ['view', 'create'],
    TICKET_MGMT: ['view', 'create'],
    MONITORING: ['view'],
  },
};
const MODULE_ORDER = [
  'DASHBOARD', 'BUSINESS_UNIT_MGMT', 'UTILITY_MGMT', 'ROLE_MGMT', 'USER_MGMT', 'MUMIN_INFO', 'EVENT_CONTRACT',
  'API_CONTRACT', 'CONTRACT_LIBRARY', 'ACCESS_REQUEST', 'TICKET_MGMT', 'MONITORING', 'AUDIT_LOG', 'CONFIGURATION',
];

let app: NestFastifyApplication;
let db: DataSource;
let jwksServer: Server;
const signers = {} as Record<SignerName, Signer>;
const roles: Record<string, string> = {};
const bu: Record<string, string> = {};
const util: Record<string, string> = {};

async function makeSigner(kid: string): Promise<Signer> {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
  return { kid, privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' } };
}

async function serviceToken(principalId: string, signer: Signer, o: { aud?: string; iss?: string; iat?: number; exp?: number } = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', typ: 'client-authentication+jwt', kid: signer.kid })
    .setIssuer(o.iss ?? principalId)
    .setSubject(principalId)
    .setAudience(o.aud ?? AUDIENCE)
    .setJti(randomUUID())
    .setIssuedAt(o.iat ?? now)
    .setExpirationTime(o.exp ?? now + 120)
    .sign(signer.privateKey);
}

interface Workspace {
  role: string;
  type: ScopeType;
  scopeId?: string | null;
}

async function userToken(itsId: string, ws?: Workspace, o: { signer?: Signer; iss?: string; aud?: string; typ?: string; tokenUse?: string; sid?: string } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const signer = o.signer ?? signers.identity;
  const scope = ws ? { role_id: roles[ws.role], scope_type: ws.type, scope_id: ws.scopeId ?? null } : {};
  return new SignJWT({ token_use: o.tokenUse ?? 'access', sid: o.sid ?? 'sid_admin_test_session', ...scope })
    .setProtectedHeader({ alg: 'RS256', typ: o.typ ?? 'at+jwt', kid: signer.kid })
    .setIssuer(o.iss ?? IDENTITY_ISSUER)
    .setSubject(itsId)
    .setAudience(o.aud ?? AUDIENCE)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + 600)
    .sign(signer.privateKey);
}

async function call(method: Method, url: string, token: string | null, payload?: unknown, headers: Record<string, string> = {}) {
  const res = await app.inject({ method, url, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers }, payload: payload as never });
  return { status: res.statusCode, body: res.body ? res.json() : undefined };
}
const svc = async (principal: 'test-federation' | 'rms-backend' | 'ops-automation', method: Method, url: string, payload?: unknown) => {
  const signer = principal === 'test-federation' ? signers.federation : principal === 'rms-backend' ? signers.rms : signers.automation;
  return call(method, url, await serviceToken(principal, signer), payload);
};
const as = async (itsId: string, ws: Workspace, method: Method, url: string, payload?: unknown) => call(method, url, await userToken(itsId, ws), payload);

const W = {
  core: (): Workspace => ({ role: 'Platform Administrator', type: 'CORE' }),
  buAdmin: (): Workspace => ({ role: 'Business Unit Admin', type: 'BUSINESS_UNIT', scopeId: bu.RMS }),
  buSub: (): Workspace => ({ role: 'BU Sub-Level Admin', type: 'BUSINESS_UNIT', scopeId: bu.RMS }),
  utilAdmin: (): Workspace => ({ role: 'Utility Admin', type: 'UTILITY', scopeId: util.Helpdesk }),
  utilSub: (): Workspace => ({ role: 'Utility Sub-Level Admin', type: 'UTILITY', scopeId: util.Helpdesk }),
};

beforeAll(async () => {
  for (const name of ['identity', 'federation', 'rms', 'automation'] as const) signers[name] = await makeSigner(`${name}-key-1`);
  signers.rogue = await makeSigner('rms-key-1');

  jwksServer = createServer((req, res) => {
    const name = (req.url ?? '').slice(1) as SignerName;
    if (!signers[name] || name === 'rogue') return void res.writeHead(404).end();
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ keys: [signers[name].jwk] }));
  });
  await new Promise<void>((resolve) => jwksServer.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${(jwksServer.address() as AddressInfo).port}`;

  Object.assign(process.env, { IDENTITY_ISSUER, IDENTITY_JWKS_URI: `${base}/identity`, AUTHZ_AUDIENCE: AUDIENCE, DEFAULT_TENANT_NAME: TENANT, CORE_PORTAL_APPLICATION_CODE: 'core-portal' });
  const env = loadEnv();

  db = new DataSource(buildDataSourceOptions(env));
  await db.initialize();
  await db.runMigrations();
  await db.query(`TRUNCATE tenants, business_units, utilities, users, applications, modules, permissions, roles, role_permissions, user_roles,
                  clients, client_origins, client_redirect_uris, client_status_history, environments, service_principals, authorization_audit_logs CASCADE`);
  const redis = new Redis(env.REDIS_URL);
  await redis.flushdb();
  await redis.quit();

  const principal = (id: string, jwks: string, scopes: string[], clients: string[] | null, status = 'ACTIVE') =>
    db.query(`INSERT INTO service_principals (principal_id, name, jwks_uri, scopes, allowed_client_ids, status) VALUES ($1, $1, $2, $3, $4, $5)`, [id, `${base}/${jwks}`, scopes, clients, status]);
  await principal('test-federation', 'federation', ['FEDERATION'], null);
  await principal('rms-backend', 'rms', ['AUTHZ_CHECK'], ['rms-web-prod']);
  await principal('ops-automation', 'automation', ['ADMIN'], null);
  await principal('revoked-backend', 'rms', ['AUTHZ_CHECK'], null, 'REVOKED');

  Object.assign(roles, (await seedCoreRbac(db, TENANT)).roles);

  app = await createApp(env);
  await app.init();
  await app.getHttpAdapter().getInstance().ready();

  // Organisation + users through the API as an ADMIN service principal (acts as CORE).
  for (const name of ['RMS', 'VMS', 'Core Services']) {
    const res = await svc('ops-automation', 'POST', '/business-units', { name });
    expect(res.status).toBe(201);
    bu[name] = res.body.bu_id;
  }
  for (const [name, parent] of [['Helpdesk', 'RMS'], ['Zone Support', 'RMS'], ['AMS', 'Core Services']]) {
    const res = await svc('ops-automation', 'POST', '/utilities', { bu_id: bu[parent], name });
    expect(res.status).toBe(201);
    util[name] = res.body.utility_id;
  }
  for (const [itsId, name] of [
    [DEMO.core, 'Platform Admin'], [DEMO.buAdmin, 'Burhan'], [DEMO.buSub, 'BU Sub Admin'], [DEMO.utilAdmin, 'Murtaza Saifuddin'],
    [DEMO.utilSub, 'Utility Sub Admin'], ['ITS22222', 'New Member'], ['ITS33333', 'VMS Member'],
  ]) {
    expect((await svc('ops-automation', 'POST', '/users', { its_id: itsId, name })).status).toBe(201);
  }
  const assign = async (itsId: string, ws: Workspace) => {
    const res = await svc('ops-automation', 'POST', '/user-roles', { its_id: itsId, role_id: roles[ws.role], scope_type: ws.type, scope_id: ws.scopeId ?? null });
    expect(res.status).toBe(201);
    return res;
  };
  await assign(DEMO.core, W.core());
  await assign(DEMO.buAdmin, W.buAdmin());
  await assign(DEMO.buSub, W.buSub());
  await assign(DEMO.utilAdmin, W.utilAdmin());
  await assign(DEMO.utilAdmin, { role: 'Utility Admin', type: 'UTILITY', scopeId: util['Zone Support'] });
  await assign(DEMO.utilAdmin, W.buAdmin());
  await assign(DEMO.utilSub, W.utilSub());
  await assign('ITS33333', { role: 'Business Unit Admin', type: 'BUSINESS_UNIT', scopeId: bu.VMS });
});

afterAll(async () => {
  await app?.close();
  await db?.destroy();
  await new Promise((resolve) => jwksServer?.close(resolve));
});

describe('schema (design document section 5)', () => {
  it('has the documented tables and columns, and created_at + updated_at on every table', async () => {
    const rows = (await db.query(
      `SELECT table_name, array_agg(column_name::text ORDER BY column_name) AS columns
         FROM information_schema.columns WHERE table_schema = 'public' AND table_name <> 'schema_migrations' GROUP BY table_name`,
    )) as { table_name: string; columns: string[] }[];
    const tables = Object.fromEntries(rows.map((r) => [r.table_name, r.columns]));
    const documented: Record<string, string[]> = {
      tenants: ['tenant_id', 'name', 'status', 'created_at'],
      business_units: ['bu_id', 'tenant_id', 'name', 'status', 'created_at'],
      utilities: ['utility_id', 'bu_id', 'name', 'status', 'created_at'],
      users: ['its_id', 'tenant_id', 'name', 'email', 'status', 'created_at'],
      modules: ['module_id', 'module_code', 'module_name', 'is_default'],
      permissions: ['permission_id', 'module_id', 'action', 'permission_code'],
      roles: ['role_id', 'tenant_id', 'role_name', 'scope_level', 'is_system_role', 'created_at'],
      role_permissions: ['role_id', 'permission_id'],
      user_roles: ['its_id', 'role_id', 'scope_type', 'scope_id', 'assigned_at'],
    };
    for (const [table, columns] of Object.entries(documented)) expect(tables[table]).toEqual(expect.arrayContaining(columns));
    for (const [table, columns] of Object.entries(tables)) {
      expect({ table, created: columns.includes('created_at'), updated: columns.includes('updated_at') }).toEqual({ table, created: true, updated: true });
    }
    expect(tables.users).not.toContain('id');
    const pk = (await db.query(
      `SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) WHERE i.indrelid = 'users'::regclass AND i.indisprimary`,
    )) as { attname: string }[];
    expect(pk.map((p) => p.attname)).toEqual(['its_id']);
  });

  it('stores no passwords, secrets or API keys', async () => {
    const rows = (await db.query(
      `SELECT table_name, column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND (column_name ILIKE '%pass%' OR column_name ILIKE '%pwd%' OR column_name ILIKE '%credential%'
              OR column_name ILIKE '%secret%' OR column_name ILIKE '%key_hash%')`,
    )) as unknown[];
    expect(rows).toEqual([]);
    expect(((await db.query(`SELECT to_regclass('public.api_clients') AS t`)) as { t: string | null }[])[0].t).toBeNull();
  });

  it('maintains updated_at on update', async () => {
    const before = ((await db.query(`SELECT updated_at FROM business_units WHERE bu_id = $1`, [bu.VMS])) as { updated_at: Date }[])[0].updated_at;
    await new Promise((r) => setTimeout(r, 20));
    await svc('ops-automation', 'PATCH', `/business-units/${bu.VMS}`, { name: 'VMS' });
    const after = ((await db.query(`SELECT updated_at FROM business_units WHERE bu_id = $1`, [bu.VMS])) as { updated_at: Date }[])[0].updated_at;
    expect(new Date(after).getTime()).toBeGreaterThan(new Date(before).getTime());
  });

  it('rejects an assignment whose scope does not match the role level (database trigger)', async () => {
    await expect(
      db.query(`INSERT INTO user_roles (its_id, role_id, scope_type, scope_id) VALUES ($1, $2, 'UTILITY', $3)`, ['ITS22222', roles['Business Unit Admin'], util.Helpdesk]),
    ).rejects.toThrow(/does not match role scope_level/);
  });
});

describe('default modules, roles and the permissions matrix', () => {
  it('seeds the 14 default modules in sidebar order', async () => {
    const res = await as(DEMO.core, W.core(), 'GET', '/modules?is_default=true');
    expect(res.status).toBe(200);
    expect(res.body.map((m: { module_code: string }) => m.module_code)).toEqual(MODULE_ORDER);
    expect(res.body.every((m: { is_default: boolean }) => m.is_default)).toBe(true);
    expect(res.body[3].permissions.map((p: { permission_code: string }) => p.permission_code)).toEqual(['ROLE_MGMT_VIEW', 'ROLE_MGMT_CREATE', 'ROLE_MGMT_EDIT', 'ROLE_MGMT_APPROVE']);
  });

  it('seeds the 5 system roles at their scope levels', async () => {
    const res = await as(DEMO.core, W.core(), 'GET', '/roles');
    const system = res.body.filter((r: { is_system_role: boolean }) => r.is_system_role).map((r: { role_name: string; scope_level: string }) => [r.role_name, r.scope_level]);
    expect(system).toEqual(
      expect.arrayContaining([
        ['Platform Administrator', 'CORE'], ['Business Unit Admin', 'BUSINESS_UNIT'], ['BU Sub-Level Admin', 'BUSINESS_UNIT'],
        ['Utility Admin', 'UTILITY'], ['Utility Sub-Level Admin', 'UTILITY'],
      ]),
    );
  });

  it.each([
    [DEMO.core, 'core'],
    [DEMO.buAdmin, 'buAdmin'],
    [DEMO.buSub, 'buSub'],
    [DEMO.utilAdmin, 'utilAdmin'],
    [DEMO.utilSub, 'utilSub'],
  ] as const)('GET /me/permissions for %s matches the matrix', async (itsId, key) => {
    const ws = W[key]();
    const res = await as(itsId, ws, 'GET', '/me/permissions');
    expect(res.status).toBe(200);
    expect(res.body).toEqual(EXPECTED[ws.role]);
    expect(Object.keys(res.body)).toEqual(MODULE_ORDER.filter((m) => m in EXPECTED[ws.role]));
  });

  it('GET /me returns the active workspace', async () => {
    const res = await as(DEMO.buAdmin, W.buAdmin(), 'GET', '/me');
    expect(res.body).toEqual({
      its_id: DEMO.buAdmin, name: 'Burhan', email: null,
      active_scope: { role_id: roles['Business Unit Admin'], role_name: 'Business Unit Admin', scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS, scope_name: 'RMS' },
    });
  });
});

describe('login workspaces and scope selection', () => {
  it('lists every assignment and flags when selection is required', async () => {
    const multi = await call('GET', '/me/assignments', await userToken(DEMO.utilAdmin));
    expect(multi.status).toBe(200);
    expect(multi.body).toMatchObject({ its_id: DEMO.utilAdmin, name: 'Murtaza Saifuddin', requires_scope_selection: true });
    expect(multi.body.assignments.map((a: { role_name: string; scope_type: string; scope_name: string }) => `${a.role_name}|${a.scope_type}|${a.scope_name}`)).toEqual([
      'Business Unit Admin|BUSINESS_UNIT|RMS', 'Utility Admin|UTILITY|Helpdesk', 'Utility Admin|UTILITY|Zone Support',
    ]);
    const single = await call('GET', '/me/assignments', await userToken(DEMO.buAdmin));
    expect(single.body).toMatchObject({ requires_scope_selection: false, assignments: [{ role_name: 'Business Unit Admin', scope_id: bu.RMS, scope_name: 'RMS' }] });
  });

  it('exposes workspaces and scope resolution to Identity Federation only', async () => {
    const list = await svc('test-federation', 'GET', `/internal/federation/users/${DEMO.utilAdmin}/assignments`);
    expect(list.body.assignments).toHaveLength(3);
    const resolved = await svc('test-federation', 'POST', '/internal/federation/assignments/resolve', {
      its_id: DEMO.utilAdmin, role_id: roles['Utility Admin'], scope_type: 'UTILITY', scope_id: util.Helpdesk,
    });
    expect(resolved.body).toEqual({
      active_scope: { role_id: roles['Utility Admin'], role_name: 'Utility Admin', scope_type: 'UTILITY', scope_id: util.Helpdesk, scope_name: 'Helpdesk' },
      permissions: EXPECTED['Utility Admin'],
    });
    const notHeld = await svc('test-federation', 'POST', '/internal/federation/assignments/resolve', {
      its_id: DEMO.utilAdmin, role_id: roles['Utility Admin'], scope_type: 'UTILITY', scope_id: util.AMS,
    });
    expect(notHeld.body.error).toBe('ASSIGNMENT_NOT_FOUND');
    expect((await call('GET', `/internal/federation/users/${DEMO.utilAdmin}/assignments`, await userToken(DEMO.core, W.core()))).status).toBe(403);
  });

  it('requires a selected, currently assigned workspace', async () => {
    expect((await call('GET', '/me/permissions', await userToken(DEMO.utilAdmin))).body.error).toBe('SCOPE_SELECTION_REQUIRED');
    expect((await call('GET', '/roles', await userToken(DEMO.utilAdmin))).body.error).toBe('SCOPE_SELECTION_REQUIRED');
    expect((await as(DEMO.buAdmin, W.core(), 'GET', '/me/permissions')).body.error).toBe('ASSIGNMENT_NOT_ACTIVE');
    expect((await as(DEMO.buAdmin, { role: 'Business Unit Admin', type: 'BUSINESS_UNIT', scopeId: bu.VMS }, 'GET', '/me/permissions')).body.error).toBe('ASSIGNMENT_NOT_ACTIVE');
    expect((await svc('ops-automation', 'GET', '/me/permissions')).body.error).toBe('USER_TOKEN_REQUIRED');
  });

  it('applies the rules of the active workspace only (same user, different scopes)', async () => {
    const zoneManager = await as(DEMO.buAdmin, W.buAdmin(), 'POST', '/roles', { role_name: 'Zone Operator', scope_level: 'UTILITY', permission_codes: ['TICKET_MGMT_VIEW'] });
    expect(zoneManager.status).toBe(201);
    const body = (scopeId: string) => ({ its_id: 'ITS22222', role_id: zoneManager.body.role_id, scope_type: 'UTILITY', scope_id: scopeId });
    const asHelpdesk = await as(DEMO.utilAdmin, W.utilAdmin(), 'POST', '/user-roles', body(util['Zone Support']));
    expect(asHelpdesk.body.error).toBe('SCOPE_NOT_PERMITTED');
    const asRmsAdmin = await as(DEMO.utilAdmin, W.buAdmin(), 'POST', '/user-roles', body(util['Zone Support']));
    expect(asRmsAdmin.status).toBe(201);
    expect(asRmsAdmin.body).toMatchObject({ its_id: 'ITS22222', role_name: 'Zone Operator', scope_type: 'UTILITY', scope_name: 'Zone Support' });
  });

  it('loses access immediately when the assignment or its scope is removed', async () => {
    const vmsWorkspace: Workspace = { role: 'Business Unit Admin', type: 'BUSINESS_UNIT', scopeId: bu.VMS };
    expect((await as('ITS33333', vmsWorkspace, 'GET', '/me/permissions')).status).toBe(200);
    expect((await svc('ops-automation', 'PATCH', `/business-units/${bu.VMS}`, { status: 'inactive' })).status).toBe(200);
    expect((await as('ITS33333', vmsWorkspace, 'GET', '/me/permissions')).body.error).toBe('ASSIGNMENT_NOT_ACTIVE');
    expect((await call('GET', '/me/assignments', await userToken('ITS33333'))).body.assignments).toEqual([]);
    await svc('ops-automation', 'PATCH', `/business-units/${bu.VMS}`, { status: 'active' });

    const revoke = await svc('ops-automation', 'DELETE', '/user-roles', { its_id: 'ITS33333', role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.VMS });
    expect(revoke.body).toMatchObject({ revoked: true });
    expect((await as('ITS33333', vmsWorkspace, 'GET', '/me/permissions')).body.error).toBe('ASSIGNMENT_NOT_ACTIVE');

    await svc('ops-automation', 'PATCH', `/users/${DEMO.utilSub}`, { status: 'suspended' });
    expect((await as(DEMO.utilSub, W.utilSub(), 'GET', '/me/permissions')).body.error).toBe('ASSIGNMENT_NOT_ACTIVE');
    await svc('ops-automation', 'PATCH', `/users/${DEMO.utilSub}`, { status: 'active' });
    expect((await as(DEMO.utilSub, W.utilSub(), 'GET', '/me/permissions')).status).toBe(200);
  });
});

describe('scope enforcement ("Can create sub-roles?")', () => {
  it('Platform Administrator manages tenants, business units and utilities; BU Admin cannot', async () => {
    expect((await as(DEMO.core, W.core(), 'POST', '/business-units', { name: 'Hall Booking' })).status).toBe(201);
    expect((await as(DEMO.buAdmin, W.buAdmin(), 'POST', '/business-units', { name: 'Nope' })).body).toMatchObject({ error: 'PERMISSION_DENIED', details: { permission: 'BUSINESS_UNIT_MGMT_CREATE' } });
    expect((await as(DEMO.buAdmin, W.buAdmin(), 'GET', '/utilities')).body.error).toBe('PERMISSION_DENIED');
    expect((await as(DEMO.core, W.core(), 'GET', '/tenants')).body.map((t: { name: string }) => t.name)).toEqual([TENANT]);
  });

  it('BU Admin creates BU- and utility-scoped custom roles, never CORE roles', async () => {
    const created = await as(DEMO.buAdmin, W.buAdmin(), 'POST', '/roles', { role_name: 'Zone Manager', scope_level: 'UTILITY', permission_codes: ['TICKET_MGMT_VIEW', 'TICKET_MGMT_CREATE'] });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ role_name: 'Zone Manager', scope_level: 'UTILITY', is_system_role: false, permissions: ['TICKET_MGMT_CREATE', 'TICKET_MGMT_VIEW'] });
    expect((await as(DEMO.buAdmin, W.buAdmin(), 'POST', '/roles', { role_name: 'Shadow Admin', scope_level: 'CORE' })).body.error).toBe('ROLE_LEVEL_NOT_PERMITTED');
  });

  it('prevents privilege escalation when creating roles, granting permissions and assigning roles', async () => {
    const escalate = await as(DEMO.buAdmin, W.buAdmin(), 'POST', '/roles', { role_name: 'Sneaky', scope_level: 'BUSINESS_UNIT', permission_codes: ['DASHBOARD_VIEW', 'BUSINESS_UNIT_MGMT_CREATE'] });
    expect(escalate.body).toMatchObject({ error: 'PERMISSION_ESCALATION', details: { missing: ['BUSINESS_UNIT_MGMT_CREATE'] } });

    const zone = (await as(DEMO.core, W.core(), 'GET', '/roles')).body.find((r: { role_name: string }) => r.role_name === 'Zone Manager');
    const grant = await as(DEMO.buAdmin, W.buAdmin(), 'POST', '/role-permissions', { role_id: zone.role_id, permission_codes: ['MUMIN_INFO_VIEW'] });
    expect(grant.body.error).toBe('PERMISSION_ESCALATION');
    expect((await as(DEMO.buAdmin, W.buAdmin(), 'POST', '/role-permissions', { role_id: zone.role_id, permission_codes: ['TICKET_MGMT_EDIT'] })).status).toBe(200);

    const coreAssign = await as(DEMO.buAdmin, W.buAdmin(), 'POST', '/user-roles', { its_id: 'ITS22222', role_id: roles['Platform Administrator'], scope_type: 'CORE' });
    expect(coreAssign.body.error).toBe('SCOPE_NOT_PERMITTED');
    const subRevokesAdmin = await as(DEMO.buSub, W.buSub(), 'DELETE', '/user-roles', { its_id: DEMO.buAdmin, role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS });
    expect(subRevokesAdmin.body.error).toBe('PERMISSION_ESCALATION');
  });

  it('protects system roles from non-CORE changes', async () => {
    const res = await as(DEMO.buAdmin, W.buAdmin(), 'POST', '/role-permissions', { role_id: roles['BU Sub-Level Admin'], permission_codes: ['DASHBOARD_VIEW'], action: 'REVOKE' });
    expect(res.body.error).toBe('SYSTEM_ROLE_PROTECTED');
    expect((await as(DEMO.buAdmin, W.buAdmin(), 'PATCH', `/roles/${roles['Business Unit Admin']}`, { role_name: 'Renamed' })).body.error).toBe('SYSTEM_ROLE_PROTECTED');
  });

  it('assigns roles only inside the workspace scope and at the matching level', async () => {
    const zone = (await as(DEMO.core, W.core(), 'GET', '/roles')).body.find((r: { role_name: string }) => r.role_name === 'Zone Manager');
    const assign = (scopeType: string, scopeId: string) => as(DEMO.buAdmin, W.buAdmin(), 'POST', '/user-roles', { its_id: 'ITS22222', role_id: zone.role_id, scope_type: scopeType, scope_id: scopeId });
    expect((await assign('UTILITY', util.Helpdesk)).status).toBe(201);
    expect((await assign('UTILITY', util.Helpdesk)).body.error).toBe('ASSIGNMENT_EXISTS');
    expect((await assign('UTILITY', util.AMS)).body.error).toBe('SCOPE_NOT_PERMITTED');
    expect((await assign('BUSINESS_UNIT', bu.RMS)).body.error).toBe('SCOPE_TYPE_MISMATCH');
    expect((await assign('UTILITY', randomUUID())).body.error).toBe('UTILITY_NOT_FOUND');
  });

  it('Utility Admin manages only utility roles in its own utility; sub-admins cannot create roles', async () => {
    expect((await as(DEMO.utilAdmin, W.utilAdmin(), 'POST', '/roles', { role_name: 'BU Helper', scope_level: 'BUSINESS_UNIT' })).body.error).toBe('ROLE_LEVEL_NOT_PERMITTED');
    const roleList = (await as(DEMO.utilAdmin, W.utilAdmin(), 'GET', '/roles')).body;
    expect(new Set(roleList.map((r: { scope_level: string }) => r.scope_level))).toEqual(new Set(['UTILITY']));
    expect((await as(DEMO.buSub, W.buSub(), 'POST', '/roles', { role_name: 'X', scope_level: 'UTILITY' })).body.error).toBe('PERMISSION_DENIED');
    expect((await as(DEMO.utilSub, W.utilSub(), 'POST', '/roles', { role_name: 'Y', scope_level: 'UTILITY' })).body.error).toBe('PERMISSION_DENIED');
  });

  it('limits user visibility and edits to the workspace scope', async () => {
    expect((await as(DEMO.buSub, W.buSub(), 'PATCH', '/users/ITS22222', { name: 'New Member (RMS)' })).status).toBe(200);
    expect((await as(DEMO.buSub, W.buSub(), 'PATCH', `/users/${DEMO.core}`, { name: 'Hacked' })).body.error).toBe('USER_OUTSIDE_SCOPE');
    expect((await as(DEMO.buSub, W.buSub(), 'GET', `/users/${DEMO.core}`)).status).toBe(404);
    const multi = await as(DEMO.buAdmin, W.buAdmin(), 'GET', `/users/${DEMO.utilAdmin}`);
    expect(multi.body.assignments).toHaveLength(3);
    const helpdeskView = await as(DEMO.utilSub, W.utilSub(), 'GET', `/users/${DEMO.utilAdmin}`);
    expect(helpdeskView.body.assignments.map((a: { scope_name: string }) => a.scope_name)).toEqual(['Helpdesk']);
  });

  it('records denied administration attempts with the actor', async () => {
    const rows = (await db.query(`SELECT actor, resource_id FROM authorization_audit_logs WHERE event_type = 'ADMIN_ACCESS_DENIED'`)) as { actor: string; resource_id: string }[];
    expect(rows).toEqual(expect.arrayContaining([{ actor: `user:${DEMO.buAdmin}`, resource_id: 'BUSINESS_UNIT_MGMT_CREATE' }]));
  });
});

describe('local session revocation (Identity signs a session out)', () => {
  const sid = 'sid_revocation_test_session';
  const revoke = (target: string) => svc('test-federation', 'POST', `/internal/federation/sessions/${target}/revoke`, undefined);

  it('accepts a token while its session is live, and refuses it once Identity revokes the sid', async () => {
    const token = await userToken(DEMO.core, W.core(), { sid });
    expect((await call('GET', '/me', token)).status).toBe(200);

    const revoked = await revoke(sid);
    expect(revoked.status).toBe(200);
    expect(revoked.body).toMatchObject({ sid, revoked: true, expires_in: expect.any(Number) });

    const after = await call('GET', '/me', token);
    expect(after.status).toBe(401);
    expect(after.body.error).toBe('SESSION_REVOKED');
    // every endpoint kind is covered, including those usable before a workspace is chosen
    expect((await call('GET', '/me/permissions', token)).status).toBe(401);
    expect((await call('GET', '/me/assignments', await userToken(DEMO.core, undefined, { sid }))).status).toBe(401);
    expect((await call('GET', '/roles', token)).status).toBe(401);
  });

  it('leaves other sessions of the same user working', async () => {
    const other = await userToken(DEMO.core, W.core(), { sid: 'sid_another_live_session' });
    expect((await call('GET', '/me', other)).status).toBe(200);
  });

  it('is only callable with a FEDERATION service token', async () => {
    expect((await call('POST', `/internal/federation/sessions/${sid}/revoke`, null)).status).toBe(401);
    expect((await svc('rms-backend', 'POST', `/internal/federation/sessions/${sid}/revoke`, undefined)).body.error).toBe('FORBIDDEN_SCOPE');
    expect((await as(DEMO.core, W.core(), 'POST', `/internal/federation/sessions/${sid}/revoke`)).body.error).toBe('SERVICE_TOKEN_REQUIRED');
    const malformed = await revoke('not a sid');
    expect([malformed.status, malformed.body.error]).toEqual([400, 'INVALID_SID']);
  });
});

describe('local sessions recorded for the Control Panel model (miqaat_core.user_sessions)', () => {
  const S = 'miqaat_core';
  let tokenSeq = 0;
  const hash = () => `${(++tokenSeq).toString(16).padStart(2, '0')}`.repeat(32).slice(0, 64);
  const future = () => new Date(Date.now() + 3600_000).toISOString();
  const record = (payload: Record<string, unknown>) => svc('test-federation', 'POST', '/internal/federation/sessions', payload);
  const sessionsFor = (sid: string) =>
    db.query(`SELECT core_sid, aud, revoked_at, user_id, role_id FROM ${S}.user_sessions WHERE core_sid = $1`, [sid]) as Promise<
      { core_sid: string; aud: string; revoked_at: Date | null; user_id: string; role_id: string }[]
    >;

  it('records a signed-in workspace, provisioning the member, tenant and role on first sign-in', async () => {
    const sid = 'sid_recorded_bu_session';
    const created = await record({
      its_id: DEMO.buAdmin, role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS,
      core_sid: sid, aud: 'miqaat-authorization', session_token: hash(), expires_at: future(), ip_address: '203.0.113.7',
    });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ core_sid: sid, session_id: expect.any(String), user_id: expect.any(String), role_id: expect.any(String) });

    const rows = await sessionsFor(sid);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ core_sid: sid, aud: 'miqaat-authorization', revoked_at: null });

    // the member and the workspace's tenant/role now exist in the Control Panel model
    const member = (await db.query(`SELECT its_id, status, has_been_active FROM ${S}.users WHERE id = $1`, [rows[0].user_id])) as {
      its_id: string | null; status: string; has_been_active: boolean;
    }[];
    expect(member[0]).toMatchObject({ its_id: DEMO.buAdmin, status: 'ACTIVE', has_been_active: true });
    const role = (await db.query(`SELECT role_level, tenant_id, role_code FROM ${S}.roles WHERE id = $1`, [rows[0].role_id])) as {
      role_level: string; tenant_id: string | null; role_code: string;
    }[];
    expect(role[0]).toMatchObject({ role_level: 'BUSINESS_UNIT_ADMIN', tenant_id: expect.any(String), role_code: 'role-business-unit-admin-rms' });
    const tenant = (await db.query(`SELECT tenant_type, name FROM ${S}.tenants WHERE id = $1`, [role[0].tenant_id])) as { tenant_type: string; name: string }[];
    expect(tenant[0]).toEqual({ tenant_type: 'BUSINESS_UNIT', name: 'RMS' });
  });

  it('reuses the member on a second sign-in and treats a replayed token hash as the same session', async () => {
    const token = hash();
    const first = await record({
      its_id: DEMO.buAdmin, role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS,
      core_sid: 'sid_recorded_twice_a', aud: 'miqaat-authorization', session_token: token, expires_at: future(),
    });
    const replay = await record({
      its_id: DEMO.buAdmin, role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS,
      core_sid: 'sid_recorded_twice_b', aud: 'miqaat-authorization', session_token: token, expires_at: future(),
    });
    expect(replay.body.session_id).toBe(first.body.session_id);
    expect(replay.body.user_id).toBe(first.body.user_id);
    expect(await sessionsFor('sid_recorded_twice_b')).toHaveLength(0);

    const members = (await db.query(`SELECT count(*) n FROM ${S}.users WHERE its_id = $1`, [DEMO.buAdmin])) as { n: string }[];
    expect(members[0].n).toBe('1');
  });

  it('refuses a workspace the user does not hold, an unknown user and an expiry in the past', async () => {
    const base = { its_id: DEMO.buAdmin, core_sid: 'sid_recorded_rejected', aud: 'miqaat-authorization', expires_at: future() };
    const notHeld = await record({ ...base, role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.VMS, session_token: hash() });
    expect([notHeld.status, notHeld.body.error]).toEqual([403, 'ASSIGNMENT_NOT_FOUND']);

    const unknown = await record({ ...base, its_id: '99999999', role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS, session_token: hash() });
    expect([unknown.status, unknown.body.error]).toEqual([404, 'USER_NOT_FOUND']);

    const past = await record({
      ...base, role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS,
      session_token: hash(), expires_at: new Date(Date.now() - 1000).toISOString(),
    });
    expect([past.status, past.body.error]).toEqual([400, 'INVALID_SESSION_EXPIRY']);
    expect(await sessionsFor('sid_recorded_rejected')).toHaveLength(0);
  });

  it('refuses a JWT as the session token: the local session is keyed by an opaque value only', async () => {
    const base = {
      its_id: DEMO.buAdmin, role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS,
      core_sid: 'sid_recorded_jwt_token', aud: 'rms-web-dev', expires_at: future(),
    };
    // a compact JWS always carries two dots, which the opaque-token pattern cannot match
    const jwtShaped = await record({ ...base, session_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzMTI2Nzg5MCJ9.c2lnbmF0dXJlLXZhbHVlLWhlcmU' });
    expect(jwtShaped.status).toBe(400);

    expect((await record({ ...base, session_token: 'too-short' })).status).toBe(400);
    expect(await sessionsFor('sid_recorded_jwt_token')).toHaveLength(0);
  });

  it('is only callable with a FEDERATION service token', async () => {
    const payload = {
      its_id: DEMO.buAdmin, role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS,
      core_sid: 'sid_recorded_forbidden', aud: 'miqaat-authorization', session_token: hash(), expires_at: future(),
    };
    expect((await call('POST', '/internal/federation/sessions', null, payload)).status).toBe(401);
    expect((await svc('rms-backend', 'POST', '/internal/federation/sessions', payload)).body.error).toBe('FORBIDDEN_SCOPE');
    expect((await as(DEMO.core, W.core(), 'POST', '/internal/federation/sessions', payload)).body.error).toBe('SERVICE_TOKEN_REQUIRED');
    expect(await sessionsFor('sid_recorded_forbidden')).toHaveLength(0);
  });

  it('marks every local session of a sid revoked when Identity signs that session out', async () => {
    const sid = 'sid_recorded_then_revoked';
    for (const _ of [1, 2]) {
      await record({
        its_id: DEMO.buAdmin, role_id: roles['Business Unit Admin'], scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS,
        core_sid: sid, aud: 'miqaat-authorization', session_token: hash(), expires_at: future(),
      });
    }
    expect((await sessionsFor(sid)).filter((r) => r.revoked_at === null)).toHaveLength(2);

    const revoked = await svc('test-federation', 'POST', `/internal/federation/sessions/${sid}/revoke`, undefined);
    expect(revoked.body).toMatchObject({ sid, revoked: true, local_sessions_revoked: 2 });
    expect((await sessionsFor(sid)).filter((r) => r.revoked_at === null)).toHaveLength(0);

    // a sid with nothing recorded still revokes the token, reporting no local sessions
    const none = await svc('test-federation', 'POST', '/internal/federation/sessions/sid_never_recorded_here/revoke', undefined);
    expect(none.body).toMatchObject({ revoked: true, local_sessions_revoked: 0 });
  });
});

describe('bearer authentication (JWKS, no API keys)', () => {
  it('rejects missing credentials, API keys, forged and foreign tokens', async () => {
    expect((await call('GET', '/roles', null)).status).toBe(401);
    expect((await call('GET', '/roles', null, undefined, { 'x-api-key': 'adm_1234abcd.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' })).status).toBe(401);
    expect((await call('GET', '/roles', await userToken(DEMO.core, W.core(), { signer: signers.rogue }))).status).toBe(401);
    expect((await call('GET', '/roles', await userToken(DEMO.core, W.core(), { iss: 'https://evil.test' }))).status).toBe(401);
    expect((await call('GET', '/roles', await userToken(DEMO.core, W.core(), { aud: 'rms-web-prod' }))).status).toBe(401);
    expect((await call('GET', '/roles', await userToken(DEMO.core, W.core(), { typ: 'JWT' }))).status).toBe(401);
    expect((await call('GET', '/health', null)).status).toBe(200);
  });

  it('verifies service tokens against the principal JWKS: key, audience, lifetime, registration, replay', async () => {
    const url = '/internal/federation/users/ITS22222/assignments';
    const now = Math.floor(Date.now() / 1000);
    expect((await call('GET', url, await serviceToken('test-federation', signers.rogue))).status).toBe(401);
    expect((await call('GET', url, await serviceToken('test-federation', signers.federation, { aud: 'another-api' }))).status).toBe(401);
    expect((await call('GET', url, await serviceToken('test-federation', signers.federation, { exp: now + 3600 }))).status).toBe(401);
    expect((await call('GET', url, await serviceToken('revoked-backend', signers.rms))).status).toBe(401);
    const token = await serviceToken('test-federation', signers.federation);
    expect((await call('GET', url, token)).status).toBe(200);
    expect((await call('GET', url, token)).status).toBe(401);
  });

  it('enforces token kinds and principal scopes', async () => {
    expect((await svc('rms-backend', 'GET', '/roles')).body.error).toBe('FORBIDDEN_SCOPE');
    expect((await as(DEMO.core, W.core(), 'POST', '/users/sync', { its_id: 'ITS44444' })).body.error).toBe('SERVICE_TOKEN_REQUIRED');
    const sync = await svc('test-federation', 'POST', '/users/sync', { its_id: 'ITS77777', password: 'x' });
    expect(sync.body.error).toBe('VALIDATION_ERROR');
    // profile sync from Identity Federation: create (name defaults to ITS ID), then partial update
    const created = await svc('test-federation', 'POST', '/users/sync', { its_id: 'ITS77777' });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ its_id: 'ITS77777', name: 'ITS77777', status: 'active', inserted: true });
    const updated = await svc('test-federation', 'POST', '/users/sync', { its_id: 'ITS77777', name: 'Synced Member', email: 'Member@Example.org' });
    expect(updated.body).toMatchObject({ its_id: 'ITS77777', name: 'Synced Member', email: 'member@example.org', status: 'active', inserted: false });
  });
});

describe('BU application authorization on Core RBAC', () => {
  beforeAll(async () => {
    expect((await svc('ops-automation', 'POST', '/environments', { code: 'PROD', name: 'Production', is_production: true })).status).toBe(201);
    for (const [code, name, owner] of [['rms', 'RMS Web', { bu_id: bu.RMS }], ['ams', 'AMS Web', { utility_id: util.AMS }], ['core-portal', 'Core Portal', {}]] as const) {
      expect((await as(DEMO.core, W.core(), 'POST', '/applications', { code, name, ...owner })).status).toBe(201);
    }
    expect((await as(DEMO.core, W.core(), 'POST', '/modules', { module_code: 'RMS_REGISTRATION', module_name: 'RMS Registration', application_code: 'rms', actions: ['view', 'create', 'edit', 'delete'] })).status).toBe(201);
    expect((await as(DEMO.core, W.core(), 'POST', '/modules', { module_code: 'RMS_REPORTS', module_name: 'RMS Reports', application_code: 'rms', actions: ['view'] })).status).toBe(201);
    expect((await as(DEMO.core, W.core(), 'POST', '/modules', { module_code: 'AMS_USERS', module_name: 'AMS Users', application_code: 'ams', actions: ['view'] })).status).toBe(201);

    for (const [clientId, appCode, host] of [['rms-web-prod', 'rms', 'rms'], ['ams-web-prod', 'ams', 'ams'], ['core-portal-prod', 'core-portal', 'core']]) {
      const created = await as(DEMO.core, W.core(), 'POST', '/clients', {
        client_id: clientId, application_code: appCode, environment_code: 'PROD', client_type: 'WEB', authentication_mode: 'EMBEDDED',
        allowed_embed_origins: [`https://${host}.example.com`], callback_uris: [`https://${host}.example.com/auth/core/callback`],
        initiate_login_uri: `https://${host}.example.com/auth/core/login`,
      });
      expect(created.status).toBe(201);
      await as(DEMO.core, W.core(), 'PATCH', `/clients/${clientId}`, { status: 'SECURITY_REVIEW' });
      expect((await as(DEMO.core, W.core(), 'PATCH', `/clients/${clientId}`, { status: 'ACTIVE' })).body.status).toBe('ACTIVE');
    }

    const operator = await as(DEMO.core, W.core(), 'POST', '/roles', { role_name: 'RMS Registration Operator', scope_level: 'BUSINESS_UNIT', permission_codes: ['RMS_REGISTRATION_VIEW', 'RMS_REGISTRATION_CREATE'] });
    roles['RMS Registration Operator'] = operator.body.role_id;
    expect((await svc('ops-automation', 'POST', '/users', { its_id: 'ITS12345', name: 'Operator' })).status).toBe(201);
    expect((await svc('ops-automation', 'POST', '/user-roles', { its_id: 'ITS12345', role_id: operator.body.role_id, scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS })).status).toBe(201);
    expect((await svc('ops-automation', 'POST', '/users', { its_id: 'ITS54321', name: 'VMS Operator' })).status).toBe(201);
    expect((await svc('ops-automation', 'POST', '/user-roles', { its_id: 'ITS54321', role_id: operator.body.role_id, scope_type: 'BUSINESS_UNIT', scope_id: bu.VMS })).status).toBe(201);
  });

  const check = (body: Record<string, string>) => svc('rms-backend', 'POST', '/authorization/check', { client_id: 'rms-web-prod', ...body });

  it('allows permissions of roles whose scope covers the application BU', async () => {
    expect((await check({ its_id: 'ITS12345', module: 'RMS_REGISTRATION', permission: 'RMS_REGISTRATION_VIEW' })).body).toEqual({
      allowed: true, its_id: 'ITS12345', client_id: 'rms-web-prod', permission: 'RMS_REGISTRATION_VIEW',
    });
    expect((await check({ its_id: 'ITS12345', permission: 'RMS_REGISTRATION_DELETE' })).body).toEqual({ allowed: false, reason: 'PERMISSION_DENIED' });
    expect((await check({ its_id: 'ITS12345', module: 'RMS_REPORTS', permission: 'RMS_REGISTRATION_VIEW' })).body.reason).toBe('MODULE_MISMATCH');
  });

  it('denies when the scope does not cover the application, or the role has no application permissions', async () => {
    expect((await check({ its_id: 'ITS54321', permission: 'RMS_REGISTRATION_VIEW' })).body.reason).toBe('APPLICATION_ACCESS_DENIED');
    expect((await check({ its_id: DEMO.core, permission: 'RMS_REGISTRATION_VIEW' })).body.reason).toBe('APPLICATION_ACCESS_DENIED');
    expect((await check({ its_id: 'ITS00000', permission: 'RMS_REGISTRATION_VIEW' })).body.reason).toBe('USER_NOT_FOUND');
  });

  it('covers the Core Portal with the default modules for CORE workspaces', async () => {
    const eff = await svc('ops-automation', 'POST', '/authorization/effective-permissions', { its_id: DEMO.core, client_id: 'core-portal-prod' });
    expect(eff.body).toMatchObject({ access: 'GRANTED', roles: [{ role_name: 'Platform Administrator', scope_type: 'CORE', scope_id: null }] });
    expect(eff.body.permissions).toEqual(expect.arrayContaining(['BUSINESS_UNIT_MGMT_CREATE', 'CONFIGURATION_EDIT']));
  });

  it("signs the result as an authorization token that verifies only with this service's own JWKS (not Identity's keys)", async () => {
    const jwks = await call('GET', '/.well-known/jwks.json', null);
    expect(jwks.status).toBe(200);
    expect(jwks.body.keys).toHaveLength(1);
    expect(Object.keys(jwks.body.keys[0]).sort()).toEqual(['alg', 'e', 'kid', 'kty', 'n', 'use']);
    expect(jwks.body.keys[0].kid).not.toBe(signers.identity.kid);

    const res = await svc('ops-automation', 'POST', '/authorization/token', { its_id: DEMO.core, client_id: 'core-portal-prod' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ token_type: 'authz+jwt', access: 'GRANTED', kid: jwks.body.keys[0].kid, expires_in: expect.any(Number) });
    const { payload, protectedHeader } = await jwtVerify(res.body.authorization_token, createLocalJWKSet(jwks.body), { audience: 'core-portal-prod', typ: 'authz+jwt', algorithms: ['RS256'] });
    expect(protectedHeader).toMatchObject({ alg: 'RS256', typ: 'authz+jwt' });
    expect(payload).toMatchObject({ sub: DEMO.core, aud: 'core-portal-prod', access: 'GRANTED', application: 'core-portal' });
    expect(payload.permissions).toEqual(expect.arrayContaining(['CONFIGURATION_EDIT']));
    await expect(jwtVerify(res.body.authorization_token, createLocalJWKSet({ keys: [signers.identity.jwk as never] }))).rejects.toThrow();

    const meta = await call('GET', '/.well-known/miqaat-authorization', null);
    expect(meta.body).toMatchObject({ authorization_token_type: 'authz+jwt', authentication_jwks_uri: expect.stringContaining('/identity') });
    expect((await svc('rms-backend', 'POST', '/authorization/token', { its_id: DEMO.core, client_id: 'core-portal-prod' })).body.error).toBe('CLIENT_NOT_PERMITTED_FOR_PRINCIPAL');
    expect((await call('POST', '/authorization/token', null, { its_id: DEMO.core, client_id: 'core-portal-prod' })).status).toBe(401);
  });

  it('restricts BU backends to their clients and applies suspension immediately', async () => {
    expect((await svc('rms-backend', 'POST', '/authorization/check', { its_id: 'ITS12345', client_id: 'ams-web-prod', permission: 'AMS_USERS_VIEW' })).body.error).toBe(
      'CLIENT_NOT_PERMITTED_FOR_PRINCIPAL',
    );
    await as(DEMO.core, W.core(), 'PATCH', '/clients/rms-web-prod', { status: 'SUSPENDED', reason: 'incident' });
    expect((await check({ its_id: 'ITS12345', permission: 'RMS_REGISTRATION_VIEW' })).body.reason).toBe('CLIENT_NOT_ACTIVE');
    await as(DEMO.core, W.core(), 'PATCH', '/clients/rms-web-prod', { status: 'ACTIVE', reason: 'resolved' });
    await svc('ops-automation', 'DELETE', '/user-roles', { its_id: 'ITS12345', role_id: roles['RMS Registration Operator'], scope_type: 'BUSINESS_UNIT', scope_id: bu.RMS });
    expect((await check({ its_id: 'ITS12345', permission: 'RMS_REGISTRATION_VIEW' })).body.reason).toBe('APPLICATION_ACCESS_DENIED');
  });

  it('lists launchable applications with the covering roles', async () => {
    const res = await svc('test-federation', 'GET', `/internal/federation/users/${DEMO.core}/applications?environment=PROD`);
    expect(res.body).toEqual([expect.objectContaining({ application_code: 'core-portal', client_id: 'core-portal-prod', launchable: true, roles: [{ code: roles['Platform Administrator'], name: 'Platform Administrator' }] })]);
  });

  it('keeps client configuration changes for CORE workspaces', async () => {
    expect((await as(DEMO.buAdmin, W.buAdmin(), 'GET', '/clients')).status).toBe(200);
    expect((await as(DEMO.buAdmin, W.buAdmin(), 'PATCH', '/clients/rms-web-prod', { status: 'SUSPENDED' })).body.error).toBe('CORE_SCOPE_REQUIRED');
  });
});

describe('Client embed origins and callbacks (add / list / remove)', () => {
  const CLIENT = '/clients/rms-web-prod';
  const originsOf = async () => ((await as(DEMO.core, W.core(), 'GET', `${CLIENT}/origins`)).body as { origin: string }[]).map((o) => o.origin).sort();
  const callbacksOf = async (type = 'CALLBACK') =>
    ((await as(DEMO.core, W.core(), 'GET', `${CLIENT}/callbacks`)).body as { uri: string; uri_type: string }[]).filter((u) => u.uri_type === type).map((u) => u.uri).sort();

  it('adds normalised origins idempotently, records who added them and exposes them to Identity Federation', async () => {
    expect(await originsOf()).toEqual(['https://rms.example.com']);
    const added = await as(DEMO.core, W.core(), 'POST', `${CLIENT}/origins`, { origin: 'https://RMS-Admin.example.com/' });
    expect(added.status).toBe(201);
    expect((added.body as { origin: string }[]).map((o) => o.origin).sort()).toEqual(['https://rms-admin.example.com', 'https://rms.example.com']);
    expect((await as(DEMO.core, W.core(), 'POST', `${CLIENT}/origins`, { origin: 'https://rms-admin.example.com' })).status).toBe(201);
    expect((await as(DEMO.core, W.core(), 'POST', `${CLIENT}/origins`, { origin: 'http://localhost:3000' })).status).toBe(201);
    expect(await originsOf()).toEqual(['http://localhost:3000', 'https://rms-admin.example.com', 'https://rms.example.com']);

    const listed = (await as(DEMO.core, W.core(), 'GET', `${CLIENT}/origins`)).body as { origin: string; created_by: string }[];
    expect(listed.find((o) => o.origin === 'http://localhost:3000')?.created_by).toBe(`user:${DEMO.core}`);
    const audit = (await db.query(`SELECT actor FROM authorization_audit_logs WHERE event_type = 'CLIENT_ORIGIN_ADDED' AND client_id = 'rms-web-prod'`)) as { actor: string }[];
    expect(audit.length).toBeGreaterThanOrEqual(3);
    expect(audit.every((a) => a.actor === `user:${DEMO.core}`)).toBe(true);

    const identityView = await svc('test-federation', 'GET', '/internal/federation/clients/rms-web-prod');
    expect(identityView.body.allowed_embed_origins).toEqual(expect.arrayContaining(['http://localhost:3000', 'https://rms-admin.example.com', 'https://rms.example.com']));
  });

  it('rejects wildcards, paths, queries, credentials, non-URLs and plain http outside localhost', async () => {
    for (const origin of ['https://*.example.com', 'https://rms.example.com/app', 'https://rms.example.com?x=1', 'https://user:pw@rms.example.com', 'rms.example.com', 'http://rms.example.com', '']) {
      const res = await as(DEMO.core, W.core(), 'POST', `${CLIENT}/origins`, { origin });
      expect([origin, res.body.error]).toEqual([origin, origin === '' ? expect.stringMatching(/INVALID_ORIGIN|VALIDATION_ERROR/) : 'INVALID_ORIGIN']);
    }
    expect(await originsOf()).toHaveLength(3);
  });

  it('allows changes only from a CORE workspace holding CONFIGURATION edit', async () => {
    const body = { origin: 'https://other.example.com' };
    expect((await call('POST', `${CLIENT}/origins`, null, body)).status).toBe(401);
    expect((await as(DEMO.buAdmin, W.buAdmin(), 'GET', `${CLIENT}/origins`)).status).toBe(200);
    expect((await as(DEMO.buAdmin, W.buAdmin(), 'POST', `${CLIENT}/origins`, body)).body.error).toBe('CORE_SCOPE_REQUIRED');
    expect((await as(DEMO.buAdmin, W.buAdmin(), 'DELETE', `${CLIENT}/origins?origin=http://localhost:3000`)).body.error).toBe('CORE_SCOPE_REQUIRED');
    expect((await as(DEMO.buSub, W.buSub(), 'GET', `${CLIENT}/origins`)).body.error).toBe('PERMISSION_DENIED');
    expect((await svc('rms-backend', 'POST', `${CLIENT}/origins`, body)).body.error).toBe('FORBIDDEN_SCOPE');
    expect(await originsOf()).toHaveLength(3);
  });

  it('removes origins by query or JSON body, 404s unknown ones and never leaves an ACTIVE embedded client without origins', async () => {
    const byQuery = await as(DEMO.core, W.core(), 'DELETE', `${CLIENT}/origins?origin=${encodeURIComponent('http://localhost:3000')}`);
    expect(byQuery.status).toBe(200);
    expect((await as(DEMO.core, W.core(), 'DELETE', `${CLIENT}/origins`, { origin: 'https://rms-admin.example.com' })).status).toBe(200);
    expect(await originsOf()).toEqual(['https://rms.example.com']);

    const unknown = await as(DEMO.core, W.core(), 'DELETE', `${CLIENT}/origins`, { origin: 'https://never-added.example.com' });
    expect([unknown.status, unknown.body.error]).toEqual([404, 'ORIGIN_NOT_REGISTERED']);
    expect((await as(DEMO.core, W.core(), 'DELETE', `${CLIENT}/origins`)).body.error).toBe('INVALID_ORIGIN');

    const last = await as(DEMO.core, W.core(), 'DELETE', `${CLIENT}/origins?origin=https://rms.example.com`);
    expect([last.status, last.body.error]).toEqual([409, 'CLIENT_CONFIGURATION_INCOMPLETE']);
    expect(await originsOf()).toEqual(['https://rms.example.com']);
    expect((await svc('test-federation', 'GET', '/internal/federation/clients/rms-web-prod')).body.allowed_embed_origins).toEqual(['https://rms.example.com']);
    const removedAudit = (await db.query(`SELECT count(*)::int AS n FROM authorization_audit_logs WHERE event_type = 'CLIENT_ORIGIN_REMOVED' AND client_id = 'rms-web-prod'`)) as { n: number }[];
    expect(removedAudit[0].n).toBe(2);
  });

  it('adds and removes callback, post-logout and back-channel URIs with the same guards', async () => {
    const second = 'https://rms.example.com/auth/core/callback-v2';
    expect((await as(DEMO.core, W.core(), 'POST', `${CLIENT}/callbacks`, { uri: second })).status).toBe(201);
    expect(await callbacksOf()).toEqual(['https://rms.example.com/auth/core/callback', second]);
    expect((await as(DEMO.core, W.core(), 'POST', `${CLIENT}/callbacks`, { uri: 'https://rms.example.com/logout/done', uri_type: 'POST_LOGOUT_REDIRECT' })).status).toBe(201);
    expect((await as(DEMO.core, W.core(), 'POST', `${CLIENT}/callbacks`, { uri: 'https://rms.example.com/auth/core/logout', uri_type: 'BACK_CHANNEL_LOGOUT' })).status).toBe(201);
    expect((await as(DEMO.core, W.core(), 'POST', `${CLIENT}/callbacks`, { uri: 'https://rms.example.com/auth/core/logout-v2', uri_type: 'BACK_CHANNEL_LOGOUT' })).status).toBe(201);
    expect(await callbacksOf('BACK_CHANNEL_LOGOUT')).toEqual(['https://rms.example.com/auth/core/logout-v2']); // exactly one back-channel URI
    expect((await as(DEMO.core, W.core(), 'POST', `${CLIENT}/callbacks`, { uri: 'https://rms.example.com/cb#frag' })).body.error).toBe('INVALID_REDIRECT_URI');

    expect((await as(DEMO.core, W.core(), 'DELETE', `${CLIENT}/callbacks?uri=${encodeURIComponent(second)}`)).status).toBe(200);
    expect((await as(DEMO.core, W.core(), 'DELETE', `${CLIENT}/callbacks`, { uri: 'https://rms.example.com/logout/done', uri_type: 'POST_LOGOUT_REDIRECT' })).status).toBe(200);
    expect((await as(DEMO.core, W.core(), 'DELETE', `${CLIENT}/callbacks`, { uri: second })).body.error).toBe('URI_NOT_REGISTERED');
    const lastCallback = await as(DEMO.core, W.core(), 'DELETE', `${CLIENT}/callbacks`, { uri: 'https://rms.example.com/auth/core/callback' });
    expect([lastCallback.status, lastCallback.body.error]).toEqual([409, 'CLIENT_CONFIGURATION_INCOMPLETE']);
    expect(await callbacksOf()).toEqual(['https://rms.example.com/auth/core/callback']);
  });
});
