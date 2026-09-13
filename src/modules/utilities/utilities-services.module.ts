import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { UtilitiesService } from './services/utilities.service';

/** Utilities — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [UtilitiesService],
  exports: [UtilitiesService],
})
export class UtilitiesServicesModule {}
