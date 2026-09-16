import { Module } from '@nestjs/common';
import { AssertionVerifierService } from './services/assertion-verifier.service';
import { AuthorizationEngine } from './services/authorization.engine';
import { AuthzCacheService } from './services/authz-cache.service';
import { LocalSessionService } from './services/local-session.service';

/** Authorization decisions and effective permissions — version-agnostic services, reused by every /vN edge. */
@Module({
  providers: [AuthorizationEngine, AuthzCacheService, AssertionVerifierService, LocalSessionService],
  exports: [AuthorizationEngine, AuthzCacheService, AssertionVerifierService, LocalSessionService],
})
export class AuthorizationServicesModule {}
