import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { ApplicationsService } from './services/applications.service';

/** Applications — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [ApplicationsService],
  exports: [ApplicationsService],
})
export class ApplicationsServicesModule {}
