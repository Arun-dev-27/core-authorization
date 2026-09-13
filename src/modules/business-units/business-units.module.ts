import { Module } from '@nestjs/common';
import { BusinessUnitsServicesModule } from './business-units-services.module';
import { BusinessUnitsV1Module } from './v1/business-units-v1.module';

/** Business units — feature aggregator. */
@Module({
  imports: [BusinessUnitsServicesModule, BusinessUnitsV1Module],
  exports: [BusinessUnitsServicesModule],
})
export class BusinessUnitsModule {}
