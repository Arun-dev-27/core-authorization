import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '../authorization-services.module';
import { SessionController } from './session.controller';

/** The Core Admin session endpoints: verify a core assertion, pick a role, resolve, check a permission, log out. */
@Module({
  imports: [AuthorizationServicesModule],
  controllers: [SessionController],
})
export class AuthorizationV1Module {}
