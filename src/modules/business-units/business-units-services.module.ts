import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { BusinessUnitsService } from './services/business-units.service';

/** Business units — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [BusinessUnitsService],
  exports: [BusinessUnitsService],
})
export class BusinessUnitsServicesModule {}
