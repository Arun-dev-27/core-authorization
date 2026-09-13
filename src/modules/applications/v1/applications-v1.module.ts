import { Module } from '@nestjs/common';
import { ApplicationsServicesModule } from '../applications-services.module';
import { ApplicationsController } from './applications.controller';

/** Applications — v1 HTTP edge. */
@Module({
  imports: [ApplicationsServicesModule],
  controllers: [ApplicationsController],
})
export class ApplicationsV1Module {}
