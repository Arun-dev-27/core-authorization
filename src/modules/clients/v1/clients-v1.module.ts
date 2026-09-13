import { Module } from '@nestjs/common';
import { ClientsServicesModule } from '../clients-services.module';
import { ClientsController } from './clients.controller';

/** Client registry and lifecycle — v1 HTTP edge. */
@Module({
  imports: [ClientsServicesModule],
  controllers: [ClientsController],
})
export class ClientsV1Module {}
