import { Module } from '@nestjs/common';
import { ClientsServicesModule } from './clients-services.module';
import { ClientsV1Module } from './v1/clients-v1.module';

/** Client registry and lifecycle — feature aggregator. */
@Module({
  imports: [ClientsServicesModule, ClientsV1Module],
  exports: [ClientsServicesModule],
})
export class ClientsModule {}
