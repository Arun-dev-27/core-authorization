import { Module } from '@nestjs/common';
import { EnvironmentsServicesModule } from './environments-services.module';
import { EnvironmentsV1Module } from './v1/environments-v1.module';

/** Environments — feature aggregator. */
@Module({
  imports: [EnvironmentsServicesModule, EnvironmentsV1Module],
  exports: [EnvironmentsServicesModule],
})
export class EnvironmentsModule {}
