import { Module } from '@nestjs/common';
import { MeServicesModule } from './me-services.module';
import { MeV1Module } from './v1/me-v1.module';

/** Signed-in user workspace and permissions — feature aggregator. */
@Module({
  imports: [MeServicesModule, MeV1Module],
  exports: [MeServicesModule],
})
export class MeModule {}
