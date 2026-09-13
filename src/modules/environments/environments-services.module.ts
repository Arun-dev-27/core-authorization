import { Module } from '@nestjs/common';
import { EnvironmentsService } from './services/environments.service';

/** Environments — version-agnostic services, reused by every /vN edge. */
@Module({
  providers: [EnvironmentsService],
  exports: [EnvironmentsService],
})
export class EnvironmentsServicesModule {}
