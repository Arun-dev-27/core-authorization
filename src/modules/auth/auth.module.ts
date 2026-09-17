import { Global, Module } from '@nestjs/common';
import { JwksResolver } from './services/jwks-resolver.service';

/**
 * JWKS resolution for verifying tokens issued elsewhere - currently the core assertion that establishes a session,
 * verified against core-authentication's JWKS.
 *
 * The bearer-token guard, service principals and administrator access tokens lived here until the catalog APIs they
 * protected (clients, applications, business units, permissions) were removed: those read tables the existing
 * admin_db does not have. Every route this service still exposes is public by design - the login page's assertion,
 * the session cookie and the session's own role decide access.
 */
@Global()
@Module({
  providers: [JwksResolver],
  exports: [JwksResolver],
})
export class AuthModule {}
