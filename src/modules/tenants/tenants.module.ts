import { Module } from '@nestjs/common';
import { TenantsServicesModule } from './tenants-services.module';
import { TenantsV1Module } from './v1/tenants-v1.module';

/** Tenants — feature aggregator. */
@Module({
  imports: [TenantsServicesModule, TenantsV1Module],
  exports: [TenantsServicesModule],
})
export class TenantsModule {}
