import { Controller, Get, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { API_V1 } from '@common/constants/api-version.constants';
import { Actor, AllowUnscopedUser, RequireActiveScope } from '@common/decorators/rbac.decorators';
import { ActorContext, UserPrincipal } from '@shared/types/principal.types';
import { MeService } from '../services/me.service';

@ApiTags('me')
@ApiBearerAuth()
@Controller({ path: 'me', version: API_V1 })
export class MeController {
  constructor(private readonly service: MeService) {}

  @Get()
  @RequireActiveScope()
  @ApiOperation({ summary: 'Signed-in user and the active workspace' })
  me(@Actor() actor: ActorContext) {
    return this.service.me(actor);
  }

  @Get('assignments')
  @AllowUnscopedUser()
  @ApiOperation({ summary: 'All workspaces (role × scope) of the signed-in user; usable before selecting one' })
  assignments(@Req() req: FastifyRequest) {
    return this.service.assignments((req.principal as UserPrincipal).itsId);
  }

  @Get('permissions')
  @RequireActiveScope()
  @ApiOperation({ summary: 'Permissions of the active workspace: { MODULE_CODE: [actions] }. Missing key = module hidden.' })
  @ApiOkResponse({ schema: { example: { DASHBOARD: ['view'], ROLE_MGMT: ['view', 'create', 'edit'], CONFIGURATION: ['view', 'edit'] } } })
  permissions(@Actor() actor: ActorContext) {
    return this.service.permissions(actor);
  }
}
