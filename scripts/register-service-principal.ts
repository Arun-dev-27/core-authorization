/**
 * Registers (or revokes) a service principal. No secret is created or stored: the caller keeps its RS256
 * private key and publishes the public JWKS at --jwks-uri; tokens it signs (typ client-authentication+jwt,
 * iss = sub = <id>, aud = AUTHZ_AUDIENCE) are verified against that JWKS.
 *
 *   npm run principal:register -- --id hbs-backend --name "HBS backend" \
 *     --jwks-uri https://hbs.example.com/.well-known/jwks.json --scopes AUTHZ_CHECK --clients hbs-web-uat,hbs-web-prod
 *   npm run principal:register -- --id hbs-backend --revoke
 */
import 'reflect-metadata';
import { parseArgs } from 'node:util';
import Redis from 'ioredis';
import { loadEnv } from '@config/configuration';
import { API_SCOPES } from '@common/constants/api-scopes.constants';
import { normalizeRedirectUri } from '@common/utils/uri-policy';
import dataSource from '@core/database/data-source';

async function main() {
  const env = loadEnv();
  const { values } = parseArgs({
    options: {
      id: { type: 'string' },
      name: { type: 'string' },
      'jwks-uri': { type: 'string' },
      scopes: { type: 'string' },
      clients: { type: 'string' },
      revoke: { type: 'boolean', default: false },
    },
  });
  if (!values.id || !/^[a-z0-9][a-z0-9-]{2,63}$/.test(values.id)) throw new Error('--id must match ^[a-z0-9][a-z0-9-]{2,63}$');
  await dataSource.initialize();

  if (values.revoke) {
    const rows = (await dataSource.query(
      `UPDATE service_principals SET status = 'REVOKED', revoked_at = now(), updated_at = now() WHERE principal_id = $1 RETURNING principal_id`,
      [values.id],
    )) as [unknown[], number];
    console.log(rows[1] ? `revoked ${values.id} (effective within 60 s on every pod)` : `principal ${values.id} not found`);
  } else {
    if (!values.name || !values['jwks-uri'] || !values.scopes) throw new Error('usage: --id --name --jwks-uri --scopes FEDERATION|AUTHZ_CHECK|ADMIN[,..] [--clients a,b]');
    const scopes = values.scopes.split(',').map((s) => s.trim());
    const invalid = scopes.filter((s) => !(API_SCOPES as readonly string[]).includes(s));
    if (invalid.length) throw new Error(`invalid scopes: ${invalid.join(', ')}`);
    const jwksUri = normalizeRedirectUri(values['jwks-uri'], env.ALLOW_INSECURE_LOCALHOST_URIS);
    const clients = values.clients ? values.clients.split(',').map((c) => c.trim()) : null;
    await dataSource.query(
      `INSERT INTO service_principals (principal_id, name, jwks_uri, scopes, allowed_client_ids) VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (principal_id) DO UPDATE SET name = EXCLUDED.name, jwks_uri = EXCLUDED.jwks_uri, scopes = EXCLUDED.scopes,
         allowed_client_ids = EXCLUDED.allowed_client_ids, status = 'ACTIVE', revoked_at = NULL, updated_at = now()`,
      [values.id, values.name, jwksUri, scopes, clients],
    );
    console.log(`registered ${values.id}: scopes=${scopes.join(',')} clients=${clients?.join(',') ?? '*'} jwks=${jwksUri}`);
  }

  const redis = new Redis(env.REDIS_URL);
  await redis.incr('authz:version');
  await redis.quit();
  await dataSource.destroy();
}

main().catch(async (error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  await dataSource.destroy().catch(() => undefined);
  process.exit(1);
});
