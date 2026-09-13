import { Module } from '@nestjs/common';
import { BusinessUnitsServicesModule } from '../business-units-services.module';
import { BusinessUnitsController } from './business-units.controller';

/** Business units — v1 HTTP edge. */
@Module({
  imports: [BusinessUnitsServicesModule],
  controllers: [BusinessUnitsController],
})
export class BusinessUnitsV1Module {}
