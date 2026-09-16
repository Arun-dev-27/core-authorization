import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseEnv } from 'node:util';
import { isIP } from 'node:net';
import { z } from 'zod';

const bool = z.enum(['true', 'false']).transform((v) => v === 'true');

/**
 * Proxy trust used to derive the client IP (`req.ip`), which session binding compares against.
 *
 *   false            direct exposure; the IP is the socket peer.
 *   <n>              number of trusted proxy hops in front of this service (Render / ALB / nginx: 1).
 *   <cidr>[,<cidr>]  trust exactly these proxy addresses.
 *
 * Plain `true` is refused on purpose. It makes Fastify take the LEFT-most X-Forwarded-For entry, and
 * that entry is whatever the client chose to send: a caller holding a stolen session cookie could set
 * `X-Forwarded-For: <victim ip>` and walk straight through the IP check. A hop count instead resolves
 * to the address our own trusted proxy observed, which the client cannot forge.
 */
/** proxy-addr's named ranges, accepted verbatim by Fastify's trustProxy. */
const PROXY_PRESETS = new Set(['loopback', 'linklocal', 'uniquelocal']);

/** A single trusted-proxy entry: a preset, a bare IP, or an IP with a valid prefix length. */
function isTrustedProxyEntry(entry: string): boolean {
  if (PROXY_PRESETS.has(entry.toLowerCase())) return true;
  const parts = entry.split('/');
  if (parts.length > 2) return false;
  const family = isIP(parts[0]);
  if (family === 0) return false;
  if (parts.length === 1) return true;
  if (!/^\d+$/.test(parts[1])) return false;
  const bits = Number(parts[1]);
  return bits >= 0 && bits <= (family === 4 ? 32 : 128);
}

const trustProxy = z
  .string()
  .default('false')
  .transform((raw, ctx): boolean | number | string[] => {
    const value = raw.trim();
    if (value === '' || value.toLowerCase() === 'false') return false;
    if (value.toLowerCase() === 'true') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'must be false, a hop count (e.g. 1), or a comma-separated list of trusted proxy CIDRs; "true" would trust a client-supplied X-Forwarded-For',
      });
      return z.NEVER;
    }
    if (/^\d+$/.test(value)) {
      const hops = Number(value);
      if (hops < 1 || hops > 10) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'hop count must be between 1 and 10' });
        return z.NEVER;
      }
      return hops;
    }
    const cidrs = value.split(',').map((part) => part.trim()).filter((part) => part.length > 0);
    if (cidrs.length === 0 || !cidrs.every(isTrustedProxyEntry)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'must be false, a hop count, or a comma-separated list of trusted proxy IPs/CIDRs (or loopback/linklocal/uniquelocal)',
      });
      return z.NEVER;
    }
    return cidrs;
  });

export const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().default(3002),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
    /**
     * Factors a session cookie is pinned to. Keep 'ip+ua' wherever the platform gives the app the
     * real client IP. Use 'ua' behind an edge that does not (Render/Cloudflare), where the visible
     * address is a shared, rotating edge IP.
     */
    SESSION_BINDING: z.enum(['ip+ua', 'ua']).default('ip+ua'),
    TRUST_PROXY: trustProxy,
    /**
     * Header carrying the real client IP, when an edge proxy provides one it overwrites on every
     * request (Cloudflare, and therefore Render: `cf-connecting-ip`). Leave unset when the service
     * is not behind such an edge; a header a client can append to must never be used here.
     */
    CLIENT_IP_HEADER: z
      .string()
      .regex(/^[a-z0-9-]{3,64}$/i)
      .optional()
      .transform((v) => (v ? v.toLowerCase() : undefined)),
    SWAGGER_ENABLED: bool.default('true'),

    AUTHZ_DB_HOST: z.string().min(1),
    AUTHZ_DB_PORT: z.coerce.number().int().positive().default(5432),
    AUTHZ_DB_USER: z.string().min(1),
    AUTHZ_DB_PASSWORD: z.string().min(1),
    AUTHZ_DB_NAME: z.string().min(1),
    AUTHZ_DB_SSL: bool.default('false'),

    REDIS_URL: z.string().url(),
    EFFECTIVE_PERMISSION_CACHE_TTL_SECONDS: z.coerce.number().int().min(0).default(60),

    ALLOW_INSECURE_LOCALHOST_URIS: bool.default('false'),
    AUDIT_ALLOW_DECISIONS: bool.default('false'),

    // Bearer authentication: every caller presents an RS256 JWT verified against a JWKS. No API keys.
    /** Issuer of admin user access tokens (Identity Federation). */
    IDENTITY_ISSUER: z.string().url(),
    /** JWKS of Identity Federation used to verify admin user access tokens. */
    IDENTITY_JWKS_URI: z.string().url(),
    /** `aud` every token presented to this service must carry. */
    AUTHZ_AUDIENCE: z.string().min(3).max(200).default('miqaat-core-authorization'),
    /** Tenant used for records created by service principals and profile sync. */
    DEFAULT_TENANT_NAME: z.string().min(1).max(200).default('Miqaat'),
    /** Application whose permissions are the default Core modules (modules.application_id IS NULL). */
    CORE_PORTAL_APPLICATION_CODE: z.string().regex(/^[a-z0-9][a-z0-9-]{1,63}$/).default('core-portal'),
    SERVICE_TOKEN_MAX_LIFETIME_SECONDS: z.coerce.number().int().min(30).max(900).default(300),
    ACCESS_TOKEN_MAX_LIFETIME_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    JWT_CLOCK_TOLERANCE_SECONDS: z.coerce.number().int().min(0).max(60).default(5),

    // Authorization's OWN signing key, separate from Identity's: signs authorization tokens (typ authz+jwt),
    // public key published at GET /.well-known/jwks.json of this service.
    /** `iss` of authorization tokens and base of this service's JWKS URI. */
    AUTHZ_ISSUER: z
      .string()
      .url()
      .transform((v) => v.replace(/\/+$/, ''))
      .default('http://localhost:3002'),
    /** PKCS#8 PEM (escaped \n allowed). Production: inject from a secret store (e.g. SSM Standard SecureString). */
    AUTHZ_SIGNING_PRIVATE_KEY: z.string().min(1).optional(),
    /** Development only: key file generated on first start when AUTHZ_SIGNING_PRIVATE_KEY is not set. */
    AUTHZ_SIGNING_KEY_FILE: z.string().min(1).default('.keys/authorization-signing.pem'),
    AUTHORIZATION_TOKEN_TTL_SECONDS: z.coerce.number().int().min(30).max(900).default(300),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production') {
      if (env.ALLOW_INSECURE_LOCALHOST_URIS) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['ALLOW_INSECURE_LOCALHOST_URIS'], message: 'must be false in production' });
      }
      if (!env.AUTHZ_SIGNING_PRIVATE_KEY) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['AUTHZ_SIGNING_PRIVATE_KEY'], message: 'is required in production (no generated key files)' });
      }
      for (const key of ['IDENTITY_ISSUER', 'IDENTITY_JWKS_URI', 'AUTHZ_ISSUER'] as const) {
        if (!env[key].startsWith('https://')) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: 'must use https in production' });
      }
    }
  });

export type Env = z.infer<typeof envSchema>;

/** Loads `.env` (or `.env.test` under jest) without overriding real environment variables. */
export function loadEnvFiles(cwd = process.cwd()): void {
  const file = process.env.ENV_FILE ?? (process.env.NODE_ENV === 'test' ? '.env.test' : '.env');
  const path = resolve(cwd, file);
  if (!existsSync(path)) return;
  // Explicit assignment (not process.loadEnvFile) so it also works inside Jest's sandboxed process.env.
  for (const [key, value] of Object.entries(parseEnv(readFileSync(path, 'utf8')))) {
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

/** Parses and validates the environment. Error messages never include values. */
export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = envSchema.safeParse(source);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid environment configuration: ${issues}`);
  }
  return parsed.data;
}
