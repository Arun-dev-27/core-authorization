import { Body, Controller, Get, HttpCode, Param, ParseUUIDPipe, Patch, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { Actor, RequirePermission } from '@common/decorators/rbac.decorators';
import { ActorContext } from '@shared/types/principal.types';
import { RolesService } from '../services/roles.service';
import { CreateRoleDto, RolePermissionsDto, RoleQueryDto, UpdateRoleDto } from './dto/role.dto';

@ApiTags('roles')
@ApiBearerAuth()
@Controller({ path: 'roles', version: API_V1 })
export class RolesController {
  constructor(private readonly service: RolesService) {}

  @Get()
  @RequirePermission('ROLE_MGMT', 'view')
  list(@Actor() actor: ActorContext, @Query() query: RoleQueryDto) {
    return this.service.list(actor, query.scope_level);
  }

  @Get(':roleId')
  @RequirePermission('ROLE_MGMT', 'view')
  get(@Actor() actor: ActorContext, @Param('roleId', new ParseUUIDPipe()) roleId: string) {
    return this.service.get(actor, roleId);
  }

  @Post()
  @RequirePermission('ROLE_MGMT', 'create')
  @ApiOperation({ summary: 'Create a custom role at or below your workspace level (e.g. "Zone Manager")' })
  create(@Actor() actor: ActorContext, @Body() dto: CreateRoleDto) {
    return this.service.create(actor, dto);
  }

  @Patch(':roleId')
  @RequirePermission('ROLE_MGMT', 'edit')
  rename(@Actor() actor: ActorContext, @Param('roleId', new ParseUUIDPipe()) roleId: string, @Body() dto: UpdateRoleDto) {
    return this.service.rename(actor, roleId, dto.role_name);
  }
}

@ApiTags('roles')
@ApiBearerAuth()
@Controller({ path: 'role-permissions', version: API_V1 })
export class RolePermissionsController {
  constructor(private readonly service: RolesService) {}

  @Post()
  @HttpCode(200)
  @RequirePermission('ROLE_MGMT', 'edit')
  @ApiOperation({ summary: 'Grant or revoke permissions on a role (no escalation beyond your own permissions)' })
  change(@Actor() actor: ActorContext, @Body() dto: RolePermissionsDto) {
    return this.service.changePermissions(actor, dto);
  }
}
