import { Module } from '@nestjs/common';
import { ModulesServicesModule } from './modules-services.module';
import { ModulesV1Module } from './v1/modules-v1.module';

/** Modules and permissions — feature aggregator. */
@Module({
  imports: [ModulesServicesModule, ModulesV1Module],
  exports: [ModulesServicesModule],
})
export class ModulesModule {}
