import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { TenantsService } from './services/tenants.service';

/** Tenants — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [TenantsService],
  exports: [TenantsService],
})
export class TenantsServicesModule {}
