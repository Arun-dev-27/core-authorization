import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { RolesService } from './services/roles.service';

/** Roles and role permissions — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [RolesService],
  exports: [RolesService],
})
export class RolesServicesModule {}
