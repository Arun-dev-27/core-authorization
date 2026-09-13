import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { ModulesService } from './services/modules.service';

/** Modules and permissions — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [ModulesService],
  exports: [ModulesService],
})
export class ModulesServicesModule {}
