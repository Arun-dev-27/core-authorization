import { Module } from '@nestjs/common';
import { AuthorizationEngine } from './services/authorization.engine';
import { AuthzCacheService } from './services/authz-cache.service';

/** Authorization decisions and effective permissions — version-agnostic services, reused by every /vN edge. */
@Module({
  providers: [AuthorizationEngine, AuthzCacheService],
  exports: [AuthorizationEngine, AuthzCacheService],
})
export class AuthorizationServicesModule {}
