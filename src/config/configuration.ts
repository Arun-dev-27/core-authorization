import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseEnv } from 'node:util';
import { z } from 'zod';

const bool = z.enum(['true', 'false']).transform((v) => v === 'true');

export const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().default(3002),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
    TRUST_PROXY: bool.default('false'),
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
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production') {
      if (env.ALLOW_INSECURE_LOCALHOST_URIS) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['ALLOW_INSECURE_LOCALHOST_URIS'], message: 'must be false in production' });
      }
      for (const key of ['IDENTITY_ISSUER', 'IDENTITY_JWKS_URI'] as const) {
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
