import { Inject, Injectable, Logger } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfig } from '@config/config.module';
import { DomainError } from '@common/errors/domain-error';
import { REDIS } from '@core/cache/redis.module';

const INVALIDATION_ATTEMPTS = 3;

/**
 * Effective-permission cache.
 *
 * Keys: authz:eff:v<version>:<its_id>:<client_id>  (TTL = EFFECTIVE_PERMISSION_CACHE_TTL_SECONDS)
 * Any write to the authorization model INCRs `authz:version`, which orphans every
 * cached entry at once, so grants/revocations take effect immediately.
 * Redis read failures degrade to direct DB evaluation. A failed invalidation is never silent:
 * the write request fails with 503 so the caller knows cached decisions may outlive the change.
 */
@Injectable()
export class AuthzCacheService {
  private readonly logger = new Logger(AuthzCacheService.name);
  static readonly VERSION_KEY = 'authz:version';

  constructor(
    @Inject(REDIS) private readonly redis: Redis,
    private readonly config: AppConfig,
  ) {}

  async get<T>(itsId: string, clientId: string): Promise<T | null> {
    if (this.config.env.EFFECTIVE_PERMISSION_CACHE_TTL_SECONDS === 0) return null;
    try {
      const version = (await this.redis.get(AuthzCacheService.VERSION_KEY)) ?? '0';
      const raw = await this.redis.get(this.key(version, itsId, clientId));
      return raw ? (JSON.parse(raw) as T) : null;
    } catch (error) {
      this.logger.warn({ msg: 'permission cache read failed; evaluating from DB', err: error });
      return null;
    }
  }

  async set(itsId: string, clientId: string, value: unknown): Promise<void> {
    const ttl = this.config.env.EFFECTIVE_PERMISSION_CACHE_TTL_SECONDS;
    if (ttl === 0) return;
    try {
      const version = (await this.redis.get(AuthzCacheService.VERSION_KEY)) ?? '0';
      await this.redis.set(this.key(version, itsId, clientId), JSON.stringify(value), 'EX', ttl);
    } catch (error) {
      this.logger.warn({ msg: 'permission cache write failed', err: error });
    }
  }

  /**
   * Must be awaited after every committed authorization-model change.
   * Retries briefly; if the version bump still fails, throws 503 CACHE_INVALIDATION_FAILED
   * (the change is saved, but a cached ALLOW could otherwise live until its TTL without anyone knowing).
   */
  async invalidateAll(): Promise<void> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= INVALIDATION_ATTEMPTS; attempt++) {
      try {
        await this.redis.incr(AuthzCacheService.VERSION_KEY);
        return;
      } catch (error) {
        lastError = error;
        if (attempt < INVALIDATION_ATTEMPTS) await new Promise((resolve) => setTimeout(resolve, 50 * attempt));
      }
    }
    this.logger.error({ msg: 'permission cache invalidation failed', attempts: INVALIDATION_ATTEMPTS, err: lastError });
    throw new DomainError(
      'CACHE_INVALIDATION_FAILED',
      `The change was saved, but cached access decisions could not be cleared; they expire within ${this.config.env.EFFECTIVE_PERMISSION_CACHE_TTL_SECONDS} seconds`,
      503,
    );
  }

  private key(version: string, itsId: string, clientId: string): string {
    return `authz:eff:v${version}:${itsId}:${clientId}`;
  }
}
