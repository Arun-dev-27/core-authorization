import { Module } from '@nestjs/common';
import { UtilitiesServicesModule } from '../utilities-services.module';
import { UtilitiesController } from './utilities.controller';

/** Utilities — v1 HTTP edge. */
@Module({
  imports: [UtilitiesServicesModule],
  controllers: [UtilitiesController],
})
export class UtilitiesV1Module {}
