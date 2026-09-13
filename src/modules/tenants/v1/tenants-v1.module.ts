import { Module } from '@nestjs/common';
import { TenantsServicesModule } from '../tenants-services.module';
import { TenantsController } from './tenants.controller';

/** Tenants — v1 HTTP edge. */
@Module({
  imports: [TenantsServicesModule],
  controllers: [TenantsController],
})
export class TenantsV1Module {}
