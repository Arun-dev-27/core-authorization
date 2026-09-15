import { Module } from '@nestjs/common';
import { AuthzSigningKeys } from './services/authz-signing-keys.service';
import { AuthzWellKnownController } from './well-known.controller';

/** Authorization's own signing key and JWKS publication (separate from Identity Federation's keys). */
@Module({
  providers: [AuthzSigningKeys],
  controllers: [AuthzWellKnownController],
  exports: [AuthzSigningKeys],
})
export class SigningModule {}
