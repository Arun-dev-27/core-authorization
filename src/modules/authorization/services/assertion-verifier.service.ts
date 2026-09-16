import { Inject, Injectable } from '@nestjs/common';
import type Redis from 'ioredis';
import { decodeProtectedHeader, errors, jwtVerify } from 'jose';
import { AppConfig } from '@config/config.module';
import { CLIENT_ID, ITS_ID } from '@common/constants/validation.constants';
import { DomainError } from '@common/errors/domain-error';
import { REDIS } from '@core/cache/redis.module';
import { JwksResolver } from '@modules/auth/services/jwks-resolver.service';

export interface VerifiedCoreAssertion {
  itsId: string;
  clientId: string;
  sid: string;
  jti: string;
  transactionId: string;
  authTime: number;
  issuedAt: number;
  expiresAt: number;
}

/** 401 with a code for logs; message stays generic for the caller. */
export class AssertionVerificationError extends DomainError {
  constructor(readonly reason: string) {
    super('INVALID_ASSERTION', 'The assertion could not be verified', 401);
  }
}

/**
 * Verifies a core_assertion (the embedded-login handoff, typ JWT) straight from a Business Unit's
 * browser - NOT a service token, NOT an admin access token. Signature is checked against
 * core-authentication's own JWKS (IDENTITY_JWKS_URI); `aud` is read from the token itself (it IS the
 * client_id) rather than fixed to AUTHZ_AUDIENCE, since this proves "this login is for that client",
 * not "this caller is a registered service".
 */
@Injectable()
export class AssertionVerifierService {
  constructor(
    private readonly config: AppConfig,
    private readonly jwks: JwksResolver,
    @Inject(REDIS) private readonly redis: Redis,
  ) {}

  async verify(token: unknown): Promise<VerifiedCoreAssertion> {
    if (typeof token !== 'string' || token.length > 8192 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
      throw new AssertionVerificationError('MALFORMED');
    }
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new AssertionVerificationError('MALFORMED');
    }
    if (header.alg !== 'RS256') throw new AssertionVerificationError('ALG_NOT_ALLOWED');
    if (typeof header.kid !== 'string' || header.kid.length === 0) throw new AssertionVerificationError('KID_MISSING');
    if (header.typ !== 'JWT') throw new AssertionVerificationError('TYP_INVALID');

    const env = this.config.env;
    let payload;
    try {
      ({ payload } = await jwtVerify(token, this.jwks.forUri(env.IDENTITY_JWKS_URI), {
        issuer: new URL(env.IDENTITY_ISSUER).origin,
        algorithms: ['RS256'],
        typ: 'JWT',
        clockTolerance: env.JWT_CLOCK_TOLERANCE_SECONDS,
        maxTokenAge: '120s',
        requiredClaims: ['sub', 'aud', 'sid', 'jti', 'txn', 'iat', 'exp', 'auth_time'],
      }));
    } catch (error) {
      throw AssertionVerifierService.mapError(error);
    }

    if (typeof payload.aud !== 'string' || !CLIENT_ID.test(payload.aud)) throw new AssertionVerificationError('AUDIENCE_INVALID');
    if (typeof payload.sub !== 'string' || !ITS_ID.test(payload.sub)) throw new AssertionVerificationError('SUBJECT_INVALID');
    if (typeof payload.jti !== 'string' || payload.jti.length < 16 || payload.jti.length > 128) throw new AssertionVerificationError('JTI_INVALID');
    if (typeof payload.sid !== 'string' || typeof payload.txn !== 'string' || typeof payload.auth_time !== 'number') {
      throw new AssertionVerificationError('CLAIMS_INVALID');
    }

    const ttl = Math.max(1, (payload.exp as number) - Math.floor(Date.now() / 1000) + env.JWT_CLOCK_TOLERANCE_SECONDS);
    const fresh = await this.redis.set(`authz:assertion-jti:${payload.jti}`, '1', 'EX', ttl, 'NX');
    if (fresh !== 'OK') throw new AssertionVerificationError('REPLAYED');

    return {
      itsId: payload.sub,
      clientId: payload.aud,
      sid: payload.sid,
      jti: payload.jti,
      transactionId: payload.txn,
      authTime: payload.auth_time,
      issuedAt: payload.iat as number,
      expiresAt: payload.exp as number,
    };
  }

  private static mapError(error: unknown): AssertionVerificationError {
    if (error instanceof errors.JWTExpired) return new AssertionVerificationError('EXPIRED');
    if (error instanceof errors.JWTClaimValidationFailed) return new AssertionVerificationError(`CLAIM_INVALID_${error.claim.toUpperCase()}`);
    if (error instanceof errors.JWKSNoMatchingKey) return new AssertionVerificationError('UNKNOWN_KID');
    if (error instanceof errors.JWSSignatureVerificationFailed) return new AssertionVerificationError('SIGNATURE_INVALID');
    if (error instanceof errors.JOSEAlgNotAllowed) return new AssertionVerificationError('ALG_NOT_ALLOWED');
    if (error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid) return new AssertionVerificationError('JWKS_UNAVAILABLE');
    return new AssertionVerificationError('VERIFICATION_FAILED');
  }
}
