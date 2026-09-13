import { Module } from '@nestjs/common';
import { ClientsServicesModule } from '@modules/clients/clients-services.module';
import { FederationServicesModule } from '../federation-services.module';
import { FederationController } from './federation.controller';

/** Internal API for Identity Federation — v1 HTTP edge. */
@Module({
  imports: [FederationServicesModule, ClientsServicesModule],
  controllers: [FederationController],
})
export class FederationV1Module {}
