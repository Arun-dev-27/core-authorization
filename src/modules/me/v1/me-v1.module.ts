import { Module } from '@nestjs/common';
import { MeServicesModule } from '../me-services.module';
import { MeController } from './me.controller';

/** Signed-in user workspace and permissions — v1 HTTP edge. */
@Module({
  imports: [MeServicesModule],
  controllers: [MeController],
})
export class MeV1Module {}
