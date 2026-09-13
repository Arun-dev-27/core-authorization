import { Module } from '@nestjs/common';
import { RolesServicesModule } from '../roles-services.module';
import { RolesController, RolePermissionsController } from './roles.controller';

/** Roles and role permissions — v1 HTTP edge. */
@Module({
  imports: [RolesServicesModule],
  controllers: [RolesController, RolePermissionsController],
})
export class RolesV1Module {}
