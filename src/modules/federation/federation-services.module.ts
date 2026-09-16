import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { FederationDirectoryService } from './services/federation-directory.service';
import { LocalSessionService } from './services/local-session.service';

/** Internal API for Identity Federation — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [FederationDirectoryService, LocalSessionService],
  exports: [FederationDirectoryService, LocalSessionService],
})
export class FederationServicesModule {}
