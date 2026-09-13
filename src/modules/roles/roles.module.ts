import { Module } from '@nestjs/common';
import { RolesServicesModule } from './roles-services.module';
import { RolesV1Module } from './v1/roles-v1.module';

/** Roles and role permissions — feature aggregator. */
@Module({
  imports: [RolesServicesModule, RolesV1Module],
  exports: [RolesServicesModule],
})
export class RolesModule {}
