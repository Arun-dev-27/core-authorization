import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from './authorization-services.module';
import { AuthorizationV1Module } from './v1/authorization-v1.module';

/** Authorization decisions and effective permissions — feature aggregator. */
@Module({
  imports: [AuthorizationServicesModule, AuthorizationV1Module],
  exports: [AuthorizationServicesModule],
})
export class AuthorizationModule {}
