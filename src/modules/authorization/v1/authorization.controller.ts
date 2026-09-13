import { Body, Controller, HttpCode, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { AppConfig } from '@config/config.module';
import { API_V1 } from '@common/constants/api-version.constants';
import { RequireScopes } from '@common/decorators/require-scopes.decorator';
import { AuditService } from '@core/audit/audit.service';
import { assertClientAllowed } from '@modules/auth/services/principal-access';
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
}
