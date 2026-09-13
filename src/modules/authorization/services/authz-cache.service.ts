import { Inject, Injectable, Logger } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfig } from '@config/config.module';
import { REDIS } from '@core/cache/redis.module';

/**
 * Effective-permission cache.
 *
 * Keys: authz:eff:v<version>:<its_id>:<client_id>  (TTL = EFFECTIVE_PERMISSION_CACHE_TTL_SECONDS)
 * Any write to the authorization model INCRs `authz:version`, which orphans every
 * cached entry at once, so grants/revocations take effect immediately.
 * Redis failures degrade to direct DB evaluation, never to a stale ALLOW.
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

  /** Must be awaited after every committed authorization-model change. */
  async invalidateAll(): Promise<void> {
    try {
      await this.redis.incr(AuthzCacheService.VERSION_KEY);
    } catch (error) {
      this.logger.error({ msg: 'permission cache invalidation failed', err: error });
    }
  }

  private key(version: string, itsId: string, clientId: string): string {
    return `authz:eff:v${version}:${itsId}:${clientId}`;
  }
}
