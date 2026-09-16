import { Global, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwksResolver } from './services/jwks-resolver.service';
import { ServicePrincipalService } from './services/service-principal.service';
import { TokenVerifier } from './services/token-verifier.service';

/** Bearer-token authentication (JWKS) for every route: service principals and administrator user tokens. */
@Global()
@Module({
  providers: [JwksResolver, ServicePrincipalService, TokenVerifier, { provide: APP_GUARD, useClass: JwtAuthGuard }],
  exports: [TokenVerifier, ServicePrincipalService, JwksResolver],
})
export class AuthModule {}
