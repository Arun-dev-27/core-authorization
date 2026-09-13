import { Module } from '@nestjs/common';
import { UtilitiesServicesModule } from './utilities-services.module';
import { UtilitiesV1Module } from './v1/utilities-v1.module';

/** Utilities — feature aggregator. */
@Module({
  imports: [UtilitiesServicesModule, UtilitiesV1Module],
  exports: [UtilitiesServicesModule],
})
export class UtilitiesModule {}
