import { Inject, Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import { decodeJwt, decodeProtectedHeader, errors, JWTPayload, JWTVerifyGetKey, jwtVerify } from 'jose';
import { AppConfig } from '@config/config.module';
import { API_SCOPES, ApiScope } from '@common/constants/api-scopes.constants';
import { SCOPE_LEVELS, ScopeLevel } from '@common/constants/rbac.constants';
import { ITS_ID, UUID } from '@common/constants/validation.constants';
import { DomainError } from '@common/errors/domain-error';
import { REDIS } from '@core/cache/redis.module';
import { ActiveScopeClaim, Principal, ServicePrincipal, UserPrincipal } from '@shared/types/principal.types';
import { JwksResolver } from './jwks-resolver.service';
import { ServicePrincipalService } from './service-principal.service';

/** Header `typ` of service tokens minted by calling services (private_key_jwt style). */
export const SERVICE_TOKEN_TYP = 'client-authentication+jwt';
/** Header `typ` of user access tokens minted by Identity Federation (RFC 9068). */
export const ACCESS_TOKEN_TYP = 'at+jwt';

const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const PRINCIPAL_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;

/** 401 with a uniform public message; `reason` is for logs only. */
export class InvalidTokenError extends DomainError {
  constructor(readonly reason: string) {
    super('INVALID_TOKEN', 'The bearer token is invalid or expired', 401);
  }
}

interface VerifyOptions {
  issuer: string;
  subject?: string;
  typ: string;
  maxLifetime: number;
  requiredClaims: string[];
}

/**
 * Verifies every bearer token presented to the Authorization service. There are no API keys:
 *
 *  - user access tokens  (typ at+jwt)                    -> Identity Federation JWKS, iss = IDENTITY_ISSUER
 *    optional active scope claims: role_id, scope_type, scope_id (set by POST /portal/select-scope)
 *  - service tokens      (typ client-authentication+jwt) -> the registered principal's own JWKS, iss = sub = principal_id
 *
 * Both: RS256 only, `kid` required, exact `aud` = AUTHZ_AUDIENCE, exp/iat with small tolerance, bounded lifetime.
 * Service tokens are single-use (jti replay protection in Redis). Tokens never carry permissions.
 */
@Injectable()
export class TokenVerifier {
  constructor(
    private readonly config: AppConfig,
    private readonly jwks: JwksResolver,
    private readonly principals: ServicePrincipalService,
    @Inject(REDIS) private readonly redis: Redis,
  ) {}

  async verify(authorization: string | undefined): Promise<Principal> {
    if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
      throw new DomainError('UNAUTHENTICATED', 'An Authorization: Bearer token is required', 401);
    }
    const token = authorization.slice(7).trim();
    if (token.length > 8192 || !COMPACT_JWS.test(token)) throw new InvalidTokenError('MALFORMED');

    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new InvalidTokenError('MALFORMED');
    }
    if (header.alg !== 'RS256') throw new InvalidTokenError('ALG_NOT_ALLOWED');
    if (typeof header.kid !== 'string' || header.kid.length === 0) throw new InvalidTokenError('KID_MISSING');

    if (header.typ === ACCESS_TOKEN_TYP) return this.verifyAccessToken(token);
    if (header.typ === SERVICE_TOKEN_TYP) return this.verifyServiceToken(token);
    throw new InvalidTokenError('TYP_NOT_ACCEPTED');
  }

  static parseActiveScope(payload: JWTPayload): ActiveScopeClaim | undefined {
    if (payload.role_id === undefined && payload.scope_type === undefined && payload.scope_id === undefined) return undefined;
    const { role_id: roleId, scope_type: scopeType } = payload;
    const scopeId = payload.scope_id ?? null;
    if (typeof roleId !== 'string' || !UUID.test(roleId)) throw new InvalidTokenError('SCOPE_INVALID');
    if (typeof scopeType !== 'string' || !(SCOPE_LEVELS as readonly string[]).includes(scopeType)) throw new InvalidTokenError('SCOPE_INVALID');
    const validId = scopeType === 'CORE' ? scopeId === null : typeof scopeId === 'string' && UUID.test(scopeId);
    if (!validId) throw new InvalidTokenError('SCOPE_INVALID');
    return { role_id: roleId, scope_type: scopeType as ScopeLevel, scope_id: scopeId as string | null };
  }

  private async verifyAccessToken(token: string): Promise<UserPrincipal> {
    const env = this.config.env;
    const payload = await this.verifySignature(token, this.jwks.forUri(env.IDENTITY_JWKS_URI), {
      issuer: new URL(env.IDENTITY_ISSUER).origin,
      typ: ACCESS_TOKEN_TYP,
      maxLifetime: env.ACCESS_TOKEN_MAX_LIFETIME_SECONDS,
      requiredClaims: ['sub', 'jti', 'iat', 'exp'],
    });
    if (payload.token_use !== 'access') throw new InvalidTokenError('TOKEN_USE_INVALID');
    if (typeof payload.sub !== 'string' || !ITS_ID.test(payload.sub)) throw new InvalidTokenError('SUBJECT_INVALID');
    const activeScope = TokenVerifier.parseActiveScope(payload);
    return {
      kind: 'user',
      id: `user:${payload.sub}`,
      itsId: payload.sub,
      sid: typeof payload.sid === 'string' ? payload.sid : undefined,
      ...(activeScope ? { activeScope } : {}),
      tokenId: payload.jti as string,
    };
  }

  private async verifyServiceToken(token: string): Promise<ServicePrincipal> {
    let unverified: JWTPayload;
    try {
      unverified = decodeJwt(token);
    } catch {
      throw new InvalidTokenError('MALFORMED');
    }
    const principalId = unverified.sub;
    if (typeof principalId !== 'string' || !PRINCIPAL_ID.test(principalId) || unverified.iss !== principalId) {
      throw new InvalidTokenError('PRINCIPAL_INVALID');
    }
    const principal = await this.principals.find(principalId);
    if (!principal || principal.status !== 'ACTIVE') throw new InvalidTokenError('PRINCIPAL_UNKNOWN_OR_REVOKED');

    const env = this.config.env;
    const payload = await this.verifySignature(token, this.jwks.forUri(principal.jwks_uri), {
      issuer: principalId,
      subject: principalId,
      typ: SERVICE_TOKEN_TYP,
      maxLifetime: env.SERVICE_TOKEN_MAX_LIFETIME_SECONDS,
      requiredClaims: ['sub', 'jti', 'iat', 'exp'],
    });

    const jti = payload.jti;
    if (typeof jti !== 'string' || jti.length < 16 || jti.length > 128) throw new InvalidTokenError('JTI_INVALID');
    const ttl = Math.max(1, (payload.exp as number) - Math.floor(Date.now() / 1000) + env.JWT_CLOCK_TOLERANCE_SECONDS);
    const fresh = await this.redis.set(`authz:svc-jti:${principalId}:${jti}`, '1', 'EX', ttl, 'NX');
    if (fresh !== 'OK') throw new InvalidTokenError('REPLAYED');

    this.principals.touch(principalId);
    return {
      kind: 'service',
      id: principalId,
      name: principal.name,
      scopes: principal.scopes.filter((s): s is ApiScope => (API_SCOPES as readonly string[]).includes(s)),
      allowedClientIds: principal.allowed_client_ids && principal.allowed_client_ids.length > 0 ? principal.allowed_client_ids : null,
      tokenId: jti,
    };
  }

  private async verifySignature(token: string, keys: JWTVerifyGetKey, options: VerifyOptions): Promise<JWTPayload> {
    const env = this.config.env;
    try {
      const { payload } = await jwtVerify(token, keys, {
        issuer: options.issuer,
        subject: options.subject,
        audience: env.AUTHZ_AUDIENCE,
        algorithms: ['RS256'],
        typ: options.typ,
        clockTolerance: env.JWT_CLOCK_TOLERANCE_SECONDS,
        maxTokenAge: `${options.maxLifetime}s`,
        requiredClaims: options.requiredClaims,
      });
      if (payload.aud !== env.AUTHZ_AUDIENCE) throw new InvalidTokenError('AUDIENCE_MISMATCH');
      if ((payload.exp as number) - (payload.iat as number) > options.maxLifetime) throw new InvalidTokenError('LIFETIME_TOO_LONG');
      return payload;
    } catch (error) {
      throw TokenVerifier.mapError(error);
    }
  }

  static mapError(error: unknown): InvalidTokenError {
    if (error instanceof InvalidTokenError) return error;
    if (error instanceof errors.JWTExpired) return new InvalidTokenError('EXPIRED');
    if (error instanceof errors.JWTClaimValidationFailed) {
      const names: Record<string, string> = { aud: 'AUDIENCE_MISMATCH', iss: 'ISSUER_MISMATCH', sub: 'SUBJECT_MISMATCH', iat: 'IAT_INVALID', typ: 'TYP_INVALID' };
      return new InvalidTokenError(names[error.claim] ?? `CLAIM_INVALID_${error.claim.toUpperCase()}`);
    }
    if (error instanceof errors.JWKSNoMatchingKey) return new InvalidTokenError('UNKNOWN_KID');
    if (error instanceof errors.JWSSignatureVerificationFailed) return new InvalidTokenError('SIGNATURE_INVALID');
    if (error instanceof errors.JOSEAlgNotAllowed) return new InvalidTokenError('ALG_NOT_ALLOWED');
    if (error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid) return new InvalidTokenError('JWKS_UNAVAILABLE');
    return new InvalidTokenError('VERIFICATION_FAILED');
  }
}
