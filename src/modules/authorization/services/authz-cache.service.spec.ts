import { Logger } from '@nestjs/common';
import type Redis from 'ioredis';
import type { AppConfig } from '@config/config.module';
import { DomainError } from '@common/errors/domain-error';
import { AuthzCacheService } from './authz-cache.service';

const config = { env: { EFFECTIVE_PERMISSION_CACHE_TTL_SECONDS: 60 } } as unknown as AppConfig;
const withIncr = (incr: jest.Mock) => new AuthzCacheService({ incr } as unknown as Redis, config);

describe('AuthzCacheService.invalidateAll', () => {
  beforeEach(() => jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined));
  afterEach(() => jest.restoreAllMocks());

  it('bumps the cache version once when Redis accepts', async () => {
    const incr = jest.fn().mockResolvedValue(1);
    await withIncr(incr).invalidateAll();
    expect(incr).toHaveBeenCalledTimes(1);
    expect(incr).toHaveBeenCalledWith(AuthzCacheService.VERSION_KEY);
  });

  it('retries a transient Redis failure', async () => {
    const incr = jest.fn().mockRejectedValueOnce(new Error('ECONNRESET')).mockResolvedValue(2);
    await withIncr(incr).invalidateAll();
    expect(incr).toHaveBeenCalledTimes(2);
  });

  it('fails with 503 instead of leaving cached decisions silently stale', async () => {
    const incr = jest.fn().mockRejectedValue(new Error('Redis down'));
    const error = await withIncr(incr).invalidateAll().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(DomainError);
    expect(error).toMatchObject({ code: 'CACHE_INVALIDATION_FAILED', status: 503 });
    expect(incr).toHaveBeenCalledTimes(3);
  });
});
