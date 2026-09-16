import { Global, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwksResolver } from './services/jwks-resolver.service';
import { ServicePrincipalService } from './services/service-principal.service';
import { SessionRevocationService } from './services/session-revocation.service';
import { TokenVerifier } from './services/token-verifier.service';

/** Bearer-token authentication (JWKS) for every route: service principals and administrator user tokens. */
@Global()
@Module({
  providers: [JwksResolver, ServicePrincipalService, SessionRevocationService, TokenVerifier, { provide: APP_GUARD, useClass: JwtAuthGuard }],
  exports: [TokenVerifier, ServicePrincipalService, SessionRevocationService],
})
export class AuthModule {}
