import { Controller, Get, Header, VERSION_NEUTRAL } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AppConfig } from '@config/config.module';
import { Public } from '@common/decorators/public.decorator';
import { AUTHORIZATION_TOKEN_TYP, AuthzSigningKeys } from './services/authz-signing-keys.service';

@ApiTags('discovery')
@Public()
@Controller({ path: '.well-known', version: VERSION_NEUTRAL })
export class AuthzWellKnownController {
  constructor(
    private readonly keys: AuthzSigningKeys,
    private readonly config: AppConfig,
  ) {}

  @Get('jwks.json')
  @Header('cache-control', 'public, max-age=300, stale-while-revalidate=60')
  @ApiOperation({ summary: "Authorization service's own public RS256 keys (verify authz+jwt tokens). Separate from Identity's JWKS." })
  jwks() {
    return this.keys.jwks();
  }

  @Get('miqaat-authorization')
  @Header('cache-control', 'public, max-age=3600')
  @ApiOperation({ summary: 'Authorization metadata: issuer, JWKS, token endpoint, and where authentication keys live' })
  metadata() {
    return {
      issuer: this.keys.issuer,
      jwks_uri: this.keys.jwksUri,
      authorization_token_endpoint: `${this.keys.issuer}/authorization/token`,
      authorization_token_type: AUTHORIZATION_TOKEN_TYP,
      authorization_token_signing_alg_values_supported: ['RS256'],
      authorization_token_lifetime_seconds: this.config.env.AUTHORIZATION_TOKEN_TTL_SECONDS,
      authorization_token_audience: 'client_id of the application',
      authentication_issuer: this.config.env.IDENTITY_ISSUER,
      authentication_jwks_uri: this.config.env.IDENTITY_JWKS_URI,
    };
  }
}
