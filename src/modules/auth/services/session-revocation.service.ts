import { Inject, Injectable, Logger } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfig } from '@config/config.module';
import { DomainError } from '@common/errors/domain-error';
import { REDIS } from '@core/cache/redis.module';

const KEY_PREFIX = 'authz:revoked-sid:';

/**
 * Sessions are authenticated and owned by Identity Federation; this service keeps only the list of sessions
 * Identity has ended, so an access token issued before the sign-out is refused here as well.
 *
 * Identity calls POST /internal/federation/sessions/:sid/revoke (service token, FEDERATION scope) on logout,
 * sign-out-everywhere, administrator force logout, user switch and re-authentication. The marker lives for the
 * longest lifetime an access token may still have, after which no token carrying that sid can be valid anyway.
 *
 * Key: authz:revoked-sid:<sid> -> "1", TTL ACCESS_TOKEN_MAX_LIFETIME_SECONDS + JWT_CLOCK_TOLERANCE_SECONDS.
 */
@Injectable()
export class SessionRevocationService {
  private readonly logger = new Logger(SessionRevocationService.name);

  constructor(
    @Inject(REDIS) private readonly redis: Redis,
    private readonly config: AppConfig,
  ) {}

  private key(sid: string): string {
    return `${KEY_PREFIX}${sid}`;
  }

  /** Longest a token carrying this sid could still be presented. */
  ttlSeconds(): number {
    return this.config.env.ACCESS_TOKEN_MAX_LIFETIME_SECONDS + this.config.env.JWT_CLOCK_TOLERANCE_SECONDS;
  }

  async revoke(sid: string): Promise<{ sid: string; revoked: true; expires_in: number }> {
    const ttl = this.ttlSeconds();
    try {
      await this.redis.set(this.key(sid), '1', 'EX', ttl);
    } catch (error) {
      this.logger.error({ msg: 'session revocation write failed', sid, err: error });
      throw new DomainError(
        'SESSION_REVOCATION_FAILED',
        'The session could not be marked as revoked; its access tokens may stay valid until they expire',
        503,
      );
    }
    this.logger.log({ msg: 'session revoked', sid, expires_in: ttl });
    return { sid, revoked: true, expires_in: ttl };
  }

  /**
   * Refuses a token whose session Identity has ended. Fails closed: when Redis cannot answer, the request is
   * refused rather than accepted on an unknown session state.
   */
  async assertNotRevoked(sid: string): Promise<void> {
    let marker: string | null;
    try {
      marker = await this.redis.get(this.key(sid));
    } catch (error) {
      this.logger.error({ msg: 'session revocation check failed', sid, err: error });
      throw new DomainError('SESSION_STATE_UNAVAILABLE', 'The session state cannot be verified right now', 503);
    }
    if (marker) throw new DomainError('SESSION_REVOKED', 'This session was signed out; sign in again', 401);
  }
}
