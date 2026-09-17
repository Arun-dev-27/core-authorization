import { LocalSessionService } from './local-session.service';

const IP = '203.0.113.7';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0';
const TOKEN = 'a'.repeat(43);

/** One live, bound user_sessions entity with its user, role and tenant, as AdminRbacRepository.findSession loads it. */
const row = (over: Record<string, unknown> = {}) => ({
  sessionToken: TOKEN,
  expiresAt: new Date(Date.now() + 3600_000),
  revokedAt: null,
  ipAddress: IP,
  userAgent: UA,
  user: { id: 'u1', itsId: '31267890', name: 'Demo Admin', email: 'demo@example.com', status: 'ACTIVE' },
  role: { id: 'r1', roleCode: 'role-platform-administrator', name: 'Platform Administrator', roleLevel: 'CORE_ADMIN', tenantId: null, tenant: null, status: 'ACTIVE' },
  ...over,
});

const rbacWith = (session: unknown) => ({ findSession: jest.fn().mockResolvedValue(session) });
const serviceWith = (rows: unknown[]) => new LocalSessionService(rbacWith(rows[0] ?? null) as never, { get: jest.fn(), set: jest.fn(), del: jest.fn() } as never);

describe('LocalSessionService.resolveSession binding', () => {
  it('resolves the session for the same IP and User-Agent', async () => {
    const result = await serviceWith([row()]).resolveSession(TOKEN, { ip: IP, userAgent: UA });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.session.user.itsId).toBe('31267890');
  });

  it('refuses a different IP', async () => {
    const result = await serviceWith([row()]).resolveSession(TOKEN, { ip: '198.51.100.9', userAgent: UA });
    expect(result).toMatchObject({ ok: false, reason: 'IP_MISMATCH' });
  });

  it('refuses a different User-Agent', async () => {
    const result = await serviceWith([row()]).resolveSession(TOKEN, { ip: IP, userAgent: 'PostmanRuntime/7.39.0' });
    expect(result).toMatchObject({ ok: false, reason: 'USER_AGENT_MISMATCH' });
  });

  it('refuses a revoked session even from the right IP and User-Agent', async () => {
    const result = await serviceWith([row({ revokedAt: new Date() })]).resolveSession(TOKEN, { ip: IP, userAgent: UA });
    expect(result).toMatchObject({ ok: false, reason: 'REVOKED' });
  });

  it('refuses an expired session even from the right IP and User-Agent', async () => {
    const result = await serviceWith([row({ expiresAt: new Date(Date.now() - 1000) })]).resolveSession(TOKEN, { ip: IP, userAgent: UA });
    expect(result).toMatchObject({ ok: false, reason: 'EXPIRED' });
  });

  it('refuses a tampered token (no row matches)', async () => {
    const result = await serviceWith([]).resolveSession(`${TOKEN.slice(0, -4)}AAAA`, { ip: IP, userAgent: UA });
    expect(result).toMatchObject({ ok: false, reason: 'NOT_FOUND' });
  });

  it.each([['', 'empty'], ['short', 'too short'], ['z'.repeat(600), 'too long']])(
    'rejects a %s token without querying the database (%s)',
    async (token) => {
      const rbac = rbacWith(row());
      const service = new LocalSessionService(rbac as never, {} as never);
      expect(await service.resolveSession(token, { ip: IP, userAgent: UA })).toMatchObject({ ok: false, reason: 'INVALID_TOKEN' });
      expect(rbac.findSession).not.toHaveBeenCalled();
    },
  );

  it('reports revocation and expiry distinctly, so the audit log can say which applied', async () => {
    const revoked = await serviceWith([row({ revokedAt: new Date() })]).resolveSession(TOKEN, { ip: IP, userAgent: UA });
    const expired = await serviceWith([row({ expiresAt: new Date(Date.now() - 1) })]).resolveSession(TOKEN, { ip: IP, userAgent: UA });
    expect([revoked, expired].map((r) => (r.ok ? 'ok' : r.reason))).toEqual(['REVOKED', 'EXPIRED']);
  });

  it('carries masked-only detail for the audit log on a mismatch', async () => {
    const result = await serviceWith([row()]).resolveSession(TOKEN, { ip: '198.51.100.9', userAgent: UA });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      const serialised = JSON.stringify(result.audit);
      expect(serialised).not.toContain(IP);
      expect(serialised).not.toContain(UA);
      expect(serialised).not.toContain(TOKEN);
    }
  });
});

describe('LocalSessionService.consumePendingSelection binding', () => {
  const pending = { userId: 'u1', itsId: '31189012', coreSid: 'sid_1', aud: 'rms-web-dev', ipAddress: IP, userAgent: UA };
  const service = (raw: string | null) => {
    const redis = { get: jest.fn().mockResolvedValue(raw), del: jest.fn().mockResolvedValue(1), set: jest.fn() };
    return { svc: new LocalSessionService({} as never, redis as never), redis };
  };

  it('consumes the selection for a matching IP and User-Agent', async () => {
    const { svc, redis } = service(JSON.stringify(pending));
    const result = await svc.consumePendingSelection('p'.repeat(43), { ip: IP, userAgent: UA });
    expect(result).toMatchObject({ ok: true });
    expect(redis.del).toHaveBeenCalled();
  });

  it.each([
    ['a different IP', { ip: '198.51.100.9', userAgent: UA }, 'IP_MISMATCH'],
    ['a different User-Agent', { ip: IP, userAgent: 'curl/8.4.0' }, 'USER_AGENT_MISMATCH'],
  ])('refuses %s and leaves the selection unconsumed', async (_label, ctx, reason) => {
    const { svc, redis } = service(JSON.stringify(pending));
    expect(await svc.consumePendingSelection('p'.repeat(43), ctx)).toMatchObject({ ok: false, reason });
    // Otherwise a mismatched caller could burn someone else's pending selection.
    expect(redis.del).not.toHaveBeenCalled();
  });

  it('refuses an unknown pending token', async () => {
    const { svc } = service(null);
    expect(await svc.consumePendingSelection('p'.repeat(43), { ip: IP, userAgent: UA })).toMatchObject({ ok: false, reason: 'NOT_FOUND' });
  });
});

describe('LocalSessionService over AdminRbacRepository', () => {
  const role = (id: string, name: string, tenant: { id: string; name: string; status: string } | null) => ({
    role: { id, roleCode: `role-${id}`, name, roleLevel: tenant ? 'BUSINESS_UNIT_ADMIN' : 'CORE_ADMIN', tenantId: tenant?.id ?? null, tenant, status: 'ACTIVE' },
  });

  it('lists the platform-wide role first, then roles by tenant name', async () => {
    const rbac = {
      findActiveAssignments: jest.fn().mockResolvedValue([
        role('b', 'Viewer', { id: 't2', name: 'RMS', status: 'ACTIVE' }),
        role('a', 'Admin', { id: 't1', name: 'AMS', status: 'ACTIVE' }),
        role('c', 'Platform Administrator', null),
      ]),
    };
    const roles = await new LocalSessionService(rbac as never, {} as never).listRolesForUser('u1');
    expect(roles.map((r) => [r.roleId, r.tenantName])).toEqual([['c', null], ['a', 'AMS'], ['b', 'RMS']]);
    expect(rbac.findActiveAssignments).toHaveBeenCalledWith('u1');
  });

  it('re-checks one chosen role through the repository', async () => {
    const rbac = { findActiveAssignments: jest.fn().mockResolvedValue([]) };
    await expect(new LocalSessionService(rbac as never, {} as never).findRoleForUser('u1', 'r9')).resolves.toBeNull();
    expect(rbac.findActiveAssignments).toHaveBeenCalledWith('u1', 'r9');
  });

  it('collapses granted module actions into modules + permissions, always with dashboard', async () => {
    const rbac = { grantedModuleActions: jest.fn().mockResolvedValue([{ module: 'usr', action: 'read' }, { module: 'usr', action: 'update' }, { module: 'aud', action: 'read' }]) };
    const result = await new LocalSessionService(rbac as never, {} as never).getModulePermissions('r1', 'BUSINESS_UNIT_ADMIN');
    expect(result).toEqual({ modules: ['dashboard', 'usr', 'aud'], permissions: { dashboard: { read: true }, usr: { read: true, update: true }, aud: { read: true } } });
    expect(rbac.grantedModuleActions).toHaveBeenCalledWith('r1', 'BUSINESS_UNIT_ADMIN');
  });

  it('exposes the live role and tenant status of a resolved session', async () => {
    const tenant = { id: 't1', name: 'RMS', status: 'INACTIVE' };
    const result = await serviceWith([row({ role: { id: 'r1', roleCode: 'role-rms', name: 'RMS Admin', roleLevel: 'BUSINESS_UNIT_ADMIN', tenantId: 't1', tenant, status: 'ACTIVE' } })]).resolveSession(TOKEN, { ip: IP, userAgent: UA });
    expect(result).toMatchObject({ ok: true, session: { roleStatus: 'ACTIVE', tenantStatus: 'INACTIVE', role: { tenantId: 't1', tenantName: 'RMS' } } });
  });
});
