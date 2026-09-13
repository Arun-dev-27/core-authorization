import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { MeService } from './services/me.service';

/** Signed-in user workspace and permissions — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [MeService],
  exports: [MeService],
})
export class MeServicesModule {}
