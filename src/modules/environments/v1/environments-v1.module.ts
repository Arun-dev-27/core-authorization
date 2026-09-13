import { Module } from '@nestjs/common';
import { EnvironmentsServicesModule } from '../environments-services.module';
import { EnvironmentsController } from './environments.controller';

/** Environments — v1 HTTP edge. */
@Module({
  imports: [EnvironmentsServicesModule],
  controllers: [EnvironmentsController],
})
export class EnvironmentsV1Module {}
