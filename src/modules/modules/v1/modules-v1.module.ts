import { Module } from '@nestjs/common';
import { ModulesServicesModule } from '../modules-services.module';
import { ModulesController, PermissionsController } from './modules.controller';

/** Modules and permissions — v1 HTTP edge. */
@Module({
  imports: [ModulesServicesModule],
  controllers: [ModulesController, PermissionsController],
})
export class ModulesV1Module {}
