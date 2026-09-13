import { Module } from '@nestjs/common';
import { ApplicationsServicesModule } from './applications-services.module';
import { ApplicationsV1Module } from './v1/applications-v1.module';

/** Applications — feature aggregator. */
@Module({
  imports: [ApplicationsServicesModule, ApplicationsV1Module],
  exports: [ApplicationsServicesModule],
})
export class ApplicationsModule {}
