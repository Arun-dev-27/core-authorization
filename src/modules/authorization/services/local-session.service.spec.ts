import { LocalSessionService } from './local-session.service';

const IP = '203.0.113.7';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0';
const TOKEN = 'a'.repeat(43);

/** One live, bound session row as resolveSession's query returns it. */
const row = (over: Record<string, unknown> = {}) => ({
  session_token: TOKEN,
  expires_at: new Date(Date.now() + 3600_000),
  revoked_at: null,
  ip_address: IP,
  user_agent: UA,
  user_id: 'u1',
  its_id: '31267890',
  user_name: 'Demo Admin',
  email: 'demo@example.com',
  user_status: 'ACTIVE',
  role_id: 'r1',
  role_code: 'role-platform-administrator',
  role_name: 'Platform Administrator',
  role_level: 'CORE_ADMIN',
  tenant_id: null,
  tenant_name: null,
  ...over,
});

const serviceWith = (rows: unknown[]) => {
  const db = { query: jest.fn().mockResolvedValue(rows) };
  const redis = { get: jest.fn(), set: jest.fn(), del: jest.fn() };
  return new LocalSessionService(db as never, redis as never);
};

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
    const result = await serviceWith([row({ revoked_at: new Date() })]).resolveSession(TOKEN, { ip: IP, userAgent: UA });
    expect(result).toMatchObject({ ok: false, reason: 'REVOKED' });
  });

  it('refuses an expired session even from the right IP and User-Agent', async () => {
    const result = await serviceWith([row({ expires_at: new Date(Date.now() - 1000) })]).resolveSession(TOKEN, { ip: IP, userAgent: UA });
    expect(result).toMatchObject({ ok: false, reason: 'EXPIRED' });
  });

  it('refuses a tampered token (no row matches)', async () => {
    const result = await serviceWith([]).resolveSession(`${TOKEN.slice(0, -4)}AAAA`, { ip: IP, userAgent: UA });
    expect(result).toMatchObject({ ok: false, reason: 'NOT_FOUND' });
  });

  it.each([['', 'empty'], ['short', 'too short'], ['z'.repeat(600), 'too long']])(
    'rejects a %s token without querying the database (%s)',
    async (token) => {
      const db = { query: jest.fn() };
      const service = new LocalSessionService(db as never, {} as never);
      expect(await service.resolveSession(token, { ip: IP, userAgent: UA })).toMatchObject({ ok: false, reason: 'INVALID_TOKEN' });
      expect(db.query).not.toHaveBeenCalled();
    },
  );

  it('reports revocation and expiry distinctly, so the audit log can say which applied', async () => {
    const revoked = await serviceWith([row({ revoked_at: new Date() })]).resolveSession(TOKEN, { ip: IP, userAgent: UA });
    const expired = await serviceWith([row({ expires_at: new Date(Date.now() - 1) })]).resolveSession(TOKEN, { ip: IP, userAgent: UA });
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
    return { svc: new LocalSessionService({ query: jest.fn() } as never, redis as never), redis };
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
