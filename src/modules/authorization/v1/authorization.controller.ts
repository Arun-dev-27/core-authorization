import { Body, Controller, HttpCode, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { AppConfig } from '@config/config.module';
import { API_V1 } from '@common/constants/api-version.constants';
import { RequireScopes } from '@common/decorators/require-scopes.decorator';
import { AuditService } from '@core/audit/audit.service';
import { assertClientAllowed } from '@modules/auth/services/principal-access';
import { AUTHORIZATION_TOKEN_TYP, AuthzSigningKeys } from '@modules/signing/services/authz-signing-keys.service';
import { AuthorizationEngine } from '../services/authorization.engine';
import { AuthorizationCheckDto } from './dto/authorization-check.dto';
import { CheckResponse } from './dto/check-response.dto';
import { EffectivePermissionsDto } from './dto/effective-permissions.dto';

@ApiTags('authorization')
@ApiBearerAuth()
@Controller({ path: 'authorization', version: API_V1 })
export class AuthorizationController {
  constructor(
    private readonly engine: AuthorizationEngine,
    private readonly audit: AuditService,
    private readonly config: AppConfig,
    private readonly signing: AuthzSigningKeys,
  ) {}

  @Post('check')
  @HttpCode(200)
  @RequireScopes('AUTHZ_CHECK')
  @ApiOperation({ summary: 'Server-side permission check for one user, client and permission (service token)' })
  @ApiOkResponse({ type: CheckResponse })
  async check(@Body() dto: AuthorizationCheckDto, @Req() req: FastifyRequest) {
    assertClientAllowed(req.principal, dto.client_id);
    const effective = await this.engine.evaluate(dto.its_id, dto.client_id);
    const decision = AuthorizationEngine.decide(effective, dto.permission, dto.module);

    if (!decision.allowed || this.config.env.AUDIT_ALLOW_DECISIONS) {
      await this.audit.record({
        eventType: 'AUTHORIZATION_CHECK',
        itsId: dto.its_id,
        clientId: dto.client_id,
        resourceType: 'permission',
        resourceId: dto.permission,
        decision: decision.allowed ? 'ALLOW' : 'DENY',
        reason: decision.reason,
        metadata: dto.module ? { module: dto.module } : undefined,
      });
    }

    return decision.allowed
      ? { allowed: true, its_id: dto.its_id, client_id: dto.client_id, permission: dto.permission }
      : { allowed: false, reason: decision.reason };
  }

  @Post('effective-permissions')
  @HttpCode(200)
  @RequireScopes('AUTHZ_CHECK')
  @ApiOperation({ summary: 'All roles, modules and permissions a user holds for a client (service token)' })
  async effectivePermissions(@Body() dto: EffectivePermissionsDto, @Req() req: FastifyRequest) {
    assertClientAllowed(req.principal, dto.client_id);
    const effective = await this.engine.evaluate(dto.its_id, dto.client_id);
    if (effective.access === 'DENIED') {
      await this.audit.record({
        eventType: 'EFFECTIVE_PERMISSIONS',
        itsId: dto.its_id,
        clientId: dto.client_id,
        decision: 'DENY',
        reason: effective.reason,
      });
    }
    return effective;
  }

  /**
   * The same evaluation as effective-permissions, returned as a signed authorization token (typ authz+jwt, RS256)
   * issued by THIS service with its own key. Applications verify it with this service's JWKS, independently of
   * the authentication (core_assertion) they verified with Identity's JWKS.
   */
  @Post('token')
  @HttpCode(200)
  @RequireScopes('AUTHZ_CHECK')
  @ApiOperation({ summary: "Signed authorization result (authz+jwt) for one user and client; verify with this service's /.well-known/jwks.json" })
  async token(@Body() dto: EffectivePermissionsDto, @Req() req: FastifyRequest) {
    assertClientAllowed(req.principal, dto.client_id);
    const effective = await this.engine.evaluate(dto.its_id, dto.client_id);
    if (effective.access === 'DENIED') {
      await this.audit.record({
        eventType: 'EFFECTIVE_PERMISSIONS',
        itsId: dto.its_id,
        clientId: dto.client_id,
        decision: 'DENY',
        reason: effective.reason,
      });
    }
    const claims = {
      access: effective.access,
      ...(effective.reason ? { reason: effective.reason } : {}),
      application: effective.application?.code ?? null,
      environment: effective.environment ?? null,
      roles: effective.roles.map((r) => ({ role_id: r.role_id, role_name: r.role_name, scope_type: r.scope_type, scope_id: r.scope_id })),
      modules: effective.modules.map((m) => m.code),
      permissions: effective.permissions,
    };
    const signed = await this.signing.sign(claims, dto.its_id, dto.client_id);
    return {
      token_type: AUTHORIZATION_TOKEN_TYP,
      authorization_token: signed.token,
      expires_in: signed.expiresIn,
      issuer: this.signing.issuer,
      jwks_uri: this.signing.jwksUri,
      kid: signed.kid,
      access: effective.access,
      ...(effective.reason ? { reason: effective.reason } : {}),
    };
  }
}
