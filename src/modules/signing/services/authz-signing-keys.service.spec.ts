import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { AppConfig } from '@config/config.module';
import type { Env } from '@config/configuration';
import { AUTHORIZATION_TOKEN_TYP, AuthzSigningKeys } from './authz-signing-keys.service';

const ISSUER = 'http://localhost:3002';
let dir: string;

const config = (overrides: Partial<Env> = {}) =>
  new AppConfig({
    NODE_ENV: 'test',
    AUTHZ_ISSUER: ISSUER,
    AUTHZ_SIGNING_KEY_FILE: join(dir, 'authorization-signing.pem'),
    AUTHORIZATION_TOKEN_TTL_SECONDS: 300,
    ...overrides,
  } as Env);

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'authz-keys-'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe('AuthzSigningKeys', () => {
  it('generates a development key once, publishes only public parameters and signs tokens verifiable with its JWKS', async () => {
    const keys = new AuthzSigningKeys(config());
    await keys.load();
    expect(existsSync(join(dir, 'authorization-signing.pem'))).toBe(true);

    const jwks = keys.jwks();
    expect(jwks.keys).toHaveLength(1);
    expect(Object.keys(jwks.keys[0]).sort()).toEqual(['alg', 'e', 'kid', 'kty', 'n', 'use']);
    expect(jwks.keys[0].kid).toMatch(/^authz-/);

    const { token, expiresIn } = await keys.sign({ access: 'GRANTED', permissions: ['RMS_REGISTRATION_VIEW'] }, '30337752', 'rms-web-dev');
    expect(expiresIn).toBe(300);
    expect(decodeProtectedHeader(token)).toEqual({ alg: 'RS256', typ: AUTHORIZATION_TOKEN_TYP, kid: jwks.keys[0].kid });
    const { payload } = await jwtVerify(token, createLocalJWKSet(jwks), { issuer: ISSUER, audience: 'rms-web-dev', typ: AUTHORIZATION_TOKEN_TYP, algorithms: ['RS256'] });
    expect(payload).toMatchObject({ sub: '30337752', access: 'GRANTED', permissions: ['RMS_REGISTRATION_VIEW'] });
    expect((payload.exp as number) - (payload.iat as number)).toBe(300);
    expect(typeof payload.jti).toBe('string');
  });

  it('keeps the same key (kid) across restarts', async () => {
    const first = new AuthzSigningKeys(config());
    await first.load();
    const second = new AuthzSigningKeys(config());
    await second.load();
    expect(second.jwks().keys[0].kid).toBe(first.jwks().keys[0].kid);
  });

  it('uses an injected PEM (escaped newlines allowed) instead of a file', async () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    const keys = new AuthzSigningKeys(config({ AUTHZ_SIGNING_PRIVATE_KEY: privateKey.replace(/\n/g, '\\n') }));
    await keys.load();
    expect(existsSync(join(dir, 'authorization-signing.pem'))).toBe(false);
    expect(keys.jwks().keys[0].kty).toBe('RSA');
  });

  it('a token signed by another key does not verify with this JWKS', async () => {
    const keys = new AuthzSigningKeys(config());
    await keys.load();
    dir = mkdtempSync(join(tmpdir(), 'authz-keys-other-'));
    const other = new AuthzSigningKeys(config());
    const { token } = await other.sign({ access: 'GRANTED' }, '30337752', 'rms-web-dev');
    await expect(jwtVerify(token, createLocalJWKSet(keys.jwks()), { issuer: ISSUER, audience: 'rms-web-dev' })).rejects.toThrow();
  });

  it('refuses production without an injected key, and keys below 2048 bits', async () => {
    await expect(new AuthzSigningKeys(config({ NODE_ENV: 'production' })).load()).rejects.toThrow(/required in production/);
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    await expect(new AuthzSigningKeys(config({ AUTHZ_SIGNING_PRIVATE_KEY: privateKey })).load()).rejects.toThrow(/minimum is 2048/);
  });
});
