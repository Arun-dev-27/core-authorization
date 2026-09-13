import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { ClientsService } from './services/clients.service';

/** Client registry and lifecycle — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [ClientsService],
  exports: [ClientsService],
})
export class ClientsServicesModule {}
