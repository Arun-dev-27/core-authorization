import { Injectable } from '@nestjs/common';
import { createRemoteJWKSet, JWTVerifyGetKey } from 'jose';

/**
 * One cached remote JWKS per URI (Identity Federation, each service principal).
 * Keys are cached for 10 minutes; an unknown `kid` triggers a refetch at most every 30 seconds,
 * so signing-key rotation at the caller propagates without configuration changes.
 */
@Injectable()
export class JwksResolver {
  private readonly sets = new Map<string, JWTVerifyGetKey>();

  forUri(uri: string): JWTVerifyGetKey {
    let set = this.sets.get(uri);
    if (!set) {
      set = createRemoteJWKSet(new URL(uri), { cacheMaxAge: 10 * 60_000, cooldownDuration: 30_000, timeoutDuration: 5_000 });
      this.sets.set(uri, set);
    }
    return set;
  }
}
