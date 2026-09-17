import { Module } from '@nestjs/common';
import { AssertionVerifierService } from './services/assertion-verifier.service';
import { LocalSessionService } from './services/local-session.service';

/** Core assertion verification and the local session over the existing admin_db RBAC tables. */
@Module({
  providers: [AssertionVerifierService, LocalSessionService],
  exports: [AssertionVerifierService, LocalSessionService],
})
export class AuthorizationServicesModule {}
