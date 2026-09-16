import { Module } from '@nestjs/common';
import { SigningModule } from '@modules/signing/signing.module';
import { AuthorizationServicesModule } from '../authorization-services.module';
import { AuthorizationController } from './authorization.controller';
import { SessionController } from './session.controller';

/** Authorization decisions and effective permissions — v1 HTTP edge. */
@Module({
  imports: [AuthorizationServicesModule, SigningModule],
  controllers: [AuthorizationController, SessionController],
})
export class AuthorizationV1Module {}
