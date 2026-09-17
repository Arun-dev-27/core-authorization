import { envSchema } from './configuration';

const base = {
  AUTHZ_DB_HOST: 'db',
  AUTHZ_DB_USER: 'u',
  AUTHZ_DB_PASSWORD: 'p',
  AUTHZ_DB_NAME: 'd',
  AUTHZ_DB_PORT: '5432',
  AUTHZ_DB_SCHEMA: 's',
  REDIS_URL: 'redis://localhost:6379',
  IDENTITY_ISSUER: 'https://identity.example.com',
  IDENTITY_JWKS_URI: 'https://identity.example.com/.well-known/jwks.json',
};
const parse = (TRUST_PROXY?: string) => envSchema.safeParse({ ...base, ...(TRUST_PROXY === undefined ? {} : { TRUST_PROXY }) });

describe('TRUST_PROXY', () => {
  it('defaults to no proxy trust', () => {
    const r = parse();
    expect(r.success).toBe(true);
    expect(r.success && r.data.TRUST_PROXY).toBe(false);
  });

  it('accepts a hop count, which is what a single load balancer needs', () => {
    const r = parse('1');
    expect(r.success && r.data.TRUST_PROXY).toBe(1);
  });

  it('accepts a list of trusted proxy CIDRs', () => {
    const r = parse('10.0.0.0/8, 192.168.0.1');
    expect(r.success && r.data.TRUST_PROXY).toEqual(['10.0.0.0/8', '192.168.0.1']);
  });

  /**
   * The point of the whole change: `true` makes Fastify read the left-most X-Forwarded-For entry,
   * which the client supplies, so a stolen cookie plus a forged header would pass the IP check.
   */
  it('refuses true, because that trusts a client-supplied X-Forwarded-For', () => {
    const r = parse('true');
    expect(r.success).toBe(false);
    if (!r.success) expect(r.error.issues[0].message).toMatch(/X-Forwarded-For/);
  });

  it.each(['0', '11', 'yes', 'maybe,'])('refuses %p', (value) => {
    expect(parse(value).success).toBe(false);
  });
});
