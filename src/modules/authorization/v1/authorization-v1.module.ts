import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '../authorization-services.module';
import { AuthorizationController } from './authorization.controller';

/** Authorization decisions and effective permissions — v1 HTTP edge. */
@Module({
  imports: [AuthorizationServicesModule],
  controllers: [AuthorizationController],
})
export class AuthorizationV1Module {}
