import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { FederationDirectoryService } from './services/federation-directory.service';

/** Internal API for Identity Federation — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [FederationDirectoryService],
  exports: [FederationDirectoryService],
})
export class FederationServicesModule {}
