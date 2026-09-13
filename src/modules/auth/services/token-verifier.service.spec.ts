import { createHmac, randomUUID } from 'node:crypto';
import { createLocalJWKSet, exportJWK, generateKeyPair, JWK, JWTVerifyGetKey, KeyLike, SignJWT } from 'jose';
import { InvalidTokenError, TokenVerifier } from './token-verifier.service';

const env = {
  IDENTITY_ISSUER: 'https://identity.miqaat.test',
  IDENTITY_JWKS_URI: 'https://identity.miqaat.test/.well-known/jwks.json',
  AUTHZ_AUDIENCE: 'miqaat-core-authorization',
  ACCESS_TOKEN_MAX_LIFETIME_SECONDS: 900,
  SERVICE_TOKEN_MAX_LIFETIME_SECONDS: 300,
  JWT_CLOCK_TOLERANCE_SECONDS: 5,
};

interface Signer {
  kid: string;
  privateKey: KeyLike;
  jwk: JWK;
  set: JWTVerifyGetKey;
}

let identity: Signer;
let rms: Signer;
let rogue: Signer;
const ROLE_ID = '6b1f3c2e-8a3d-4a5b-9c1e-2d3f4a5b6c7d';
const BU_ID = '0f8e7d6c-5b4a-4938-8271-605f4e3d2c1b';

async function makeSigner(kid: string): Promise<Signer> {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  return { kid, privateKey, jwk, set: createLocalJWKSet({ keys: [jwk] }) };
}

const principals: Record<string, unknown> = {
  'rms-backend': { principal_id: 'rms-backend', name: 'RMS', jwks_uri: 'https://rms.test/jwks', scopes: ['AUTHZ_CHECK', 'BOGUS'], allowed_client_ids: ['rms-web-prod'], status: 'ACTIVE' },
  'old-backend': { principal_id: 'old-backend', name: 'Old', jwks_uri: 'https://rms.test/jwks', scopes: ['AUTHZ_CHECK'], allowed_client_ids: null, status: 'REVOKED' },
};

function verifier() {
  const seen = new Set<string>();
  const redis = { set: async (key: string) => (seen.has(key) ? null : (seen.add(key), 'OK')) };
  const jwks = { forUri: (uri: string) => (uri === env.IDENTITY_JWKS_URI ? identity.set : rms.set) };
  const registry = { find: async (id: string) => principals[id] ?? null, touch: () => undefined };
  return new TokenVerifier({ env } as never, jwks as never, registry as never, redis as never);
}

async function serviceToken(o: { sub?: string; iss?: string; aud?: string; iat?: number; exp?: number; typ?: string; signer?: Signer } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const s = o.signer ?? rms;
  const sub = o.sub ?? 'rms-backend';
  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', typ: o.typ ?? 'client-authentication+jwt', kid: s.kid })
    .setIssuer(o.iss ?? sub)
    .setSubject(sub)
    .setAudience(o.aud ?? env.AUTHZ_AUDIENCE)
    .setJti(randomUUID())
    .setIssuedAt(o.iat ?? now)
    .setExpirationTime(o.exp ?? now + 120)
    .sign(s.privateKey);
}

async function accessToken(o: { sub?: string; iss?: string; aud?: string; typ?: string; tokenUse?: string | null; signer?: Signer; scope?: Record<string, unknown> } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const s = o.signer ?? identity;
  const claims = o.tokenUse === null ? {} : { token_use: o.tokenUse ?? 'access' };
  return new SignJWT({ ...claims, sid: 'sid_admin_session_1', ...(o.scope ?? {}) })
    .setProtectedHeader({ alg: 'RS256', typ: o.typ ?? 'at+jwt', kid: s.kid })
    .setIssuer(o.iss ?? env.IDENTITY_ISSUER)
    .setSubject(o.sub ?? '30337752')
    .setAudience(o.aud ?? env.AUTHZ_AUDIENCE)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + 600)
    .sign(s.privateKey);
}

async function expectReason(promise: Promise<unknown>, reason: string) {
  await expect(promise).rejects.toBeInstanceOf(InvalidTokenError);
  await expect(promise).rejects.toMatchObject({ reason, status: 401 });
}

beforeAll(async () => {
  identity = await makeSigner('identity-key-1');
  rms = await makeSigner('rms-key-1');
  rogue = await makeSigner('rms-key-1'); // same kid, different key
});

describe('TokenVerifier (JWKS bearer authentication, no API keys)', () => {
  describe('service tokens', () => {
    it('accepts a token signed with the principal key and exposes only known scopes', async () => {
      await expect(verifier().verify(`Bearer ${await serviceToken()}`)).resolves.toMatchObject({
        kind: 'service',
        id: 'rms-backend',
        scopes: ['AUTHZ_CHECK'],
        allowedClientIds: ['rms-web-prod'],
      });
    });

    it('is single-use (jti replay protection)', async () => {
      const v = verifier();
      const token = await serviceToken();
      await v.verify(`Bearer ${token}`);
      await expectReason(v.verify(`Bearer ${token}`), 'REPLAYED');
    });

    it('rejects unknown and revoked principals, and issuer/subject mismatch', async () => {
      await expectReason(verifier().verify(`Bearer ${await serviceToken({ sub: 'nobody-backend' })}`), 'PRINCIPAL_UNKNOWN_OR_REVOKED');
      await expectReason(verifier().verify(`Bearer ${await serviceToken({ sub: 'old-backend' })}`), 'PRINCIPAL_UNKNOWN_OR_REVOKED');
      await expectReason(verifier().verify(`Bearer ${await serviceToken({ iss: 'someone-else' })}`), 'PRINCIPAL_INVALID');
    });

    it('rejects a different key using the trusted kid', async () => {
      await expectReason(verifier().verify(`Bearer ${await serviceToken({ signer: rogue })}`), 'SIGNATURE_INVALID');
    });

    it('enforces exact audience, expiry and maximum lifetime', async () => {
      const now = Math.floor(Date.now() / 1000);
      await expectReason(verifier().verify(`Bearer ${await serviceToken({ aud: 'other-api' })}`), 'AUDIENCE_MISMATCH');
      await expectReason(verifier().verify(`Bearer ${await serviceToken({ iat: now - 900, exp: now - 600 })}`), 'EXPIRED');
      await expectReason(verifier().verify(`Bearer ${await serviceToken({ iat: now, exp: now + 3600 })}`), 'LIFETIME_TOO_LONG');
    });
  });

  describe('administrator access tokens', () => {
    it('accepts Identity-issued at+jwt tokens without a workspace (before POST /select-scope)', async () => {
      const principal = await verifier().verify(`Bearer ${await accessToken()}`);
      expect(principal).toEqual({ kind: 'user', id: 'user:30337752', itsId: '30337752', sid: 'sid_admin_session_1', tokenId: expect.any(String) });
    });

    it('reads the active scope (role + scope) but never permissions from the token', async () => {
      const core = await verifier().verify(`Bearer ${await accessToken({ scope: { role_id: ROLE_ID, scope_type: 'CORE', scope_id: null } })}`);
      expect(core).toMatchObject({ activeScope: { role_id: ROLE_ID, scope_type: 'CORE', scope_id: null } });
      const bu = await verifier().verify(`Bearer ${await accessToken({ scope: { role_id: ROLE_ID, scope_type: 'BUSINESS_UNIT', scope_id: BU_ID, permissions: ['BUSINESS_UNIT_MGMT_CREATE'] } })}`);
      expect(bu).toMatchObject({ activeScope: { role_id: ROLE_ID, scope_type: 'BUSINESS_UNIT', scope_id: BU_ID } });
      expect(JSON.stringify(bu)).not.toContain('BUSINESS_UNIT_MGMT_CREATE');
    });

    it('rejects malformed scope claims', async () => {
      await expectReason(verifier().verify(`Bearer ${await accessToken({ scope: { role_id: 'r-001', scope_type: 'CORE' } })}`), 'SCOPE_INVALID');
      await expectReason(verifier().verify(`Bearer ${await accessToken({ scope: { role_id: ROLE_ID, scope_type: 'GALAXY', scope_id: BU_ID } })}`), 'SCOPE_INVALID');
      await expectReason(verifier().verify(`Bearer ${await accessToken({ scope: { role_id: ROLE_ID, scope_type: 'CORE', scope_id: BU_ID } })}`), 'SCOPE_INVALID');
      await expectReason(verifier().verify(`Bearer ${await accessToken({ scope: { role_id: ROLE_ID, scope_type: 'UTILITY', scope_id: null } })}`), 'SCOPE_INVALID');
    });

    it('rejects tokens not signed by Identity Federation or with the wrong issuer/audience', async () => {
      await expectReason(verifier().verify(`Bearer ${await accessToken({ signer: rms })}`), 'UNKNOWN_KID');
      await expectReason(verifier().verify(`Bearer ${await accessToken({ iss: 'https://evil.test' })}`), 'ISSUER_MISMATCH');
      await expectReason(verifier().verify(`Bearer ${await accessToken({ aud: 'rms-web-prod' })}`), 'AUDIENCE_MISMATCH');
      await expectReason(verifier().verify(`Bearer ${await accessToken({ tokenUse: null })}`), 'TOKEN_USE_INVALID');
    });

    it('rejects login assertions and other token types (typ confusion)', async () => {
      await expectReason(verifier().verify(`Bearer ${await accessToken({ typ: 'JWT', aud: 'rms-web-prod' })}`), 'TYP_NOT_ACCEPTED');
      await expectReason(verifier().verify(`Bearer ${await accessToken({ typ: 'logout+jwt' })}`), 'TYP_NOT_ACCEPTED');
      await expectReason(verifier().verify(`Bearer ${await serviceToken({ signer: identity, sub: '30337752' })}`), 'PRINCIPAL_UNKNOWN_OR_REVOKED');
    });
  });

  describe('malformed and downgraded credentials', () => {
    it('requires a Bearer token (API keys are not accepted)', async () => {
      await expect(verifier().verify(undefined)).rejects.toMatchObject({ code: 'UNAUTHENTICATED', status: 401 });
      await expect(verifier().verify('adm_1234abcd.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
      await expectReason(verifier().verify('Bearer adm_1234abcd.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), 'MALFORMED');
    });

    it('rejects alg=none and HS256 tokens', async () => {
      const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
      const now = Math.floor(Date.now() / 1000);
      const body = b64({ iss: env.IDENTITY_ISSUER, sub: '30337752', aud: env.AUTHZ_AUDIENCE, token_use: 'access', jti: randomUUID(), iat: now, exp: now + 60 });
      const none = `${b64({ alg: 'none', typ: 'at+jwt', kid: 'identity-key-1' })}.${body}.AAAA`;
      await expectReason(verifier().verify(`Bearer ${none}`), 'ALG_NOT_ALLOWED');
      const hsHeader = b64({ alg: 'HS256', typ: 'at+jwt', kid: 'identity-key-1' });
      const sig = createHmac('sha256', JSON.stringify(identity.jwk)).update(`${hsHeader}.${body}`).digest('base64url');
      await expectReason(verifier().verify(`Bearer ${hsHeader}.${body}.${sig}`), 'ALG_NOT_ALLOWED');
    });
  });
});
