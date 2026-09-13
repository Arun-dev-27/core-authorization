import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { ITS_ID } from '@common/constants/validation.constants';
import { Actor, RequirePermission } from '@common/decorators/rbac.decorators';
import { RequireScopes } from '@common/decorators/require-scopes.decorator';
import { DomainError } from '@common/errors/domain-error';
import { ActorContext } from '@shared/types/principal.types';
import { UsersService } from '../services/users.service';
import { CreateUserDto, SyncUserDto, UpdateUserDto, UserRoleDto } from './dto/user.dto';

function itsId(value: string): string {
  if (!ITS_ID.test(value)) throw new DomainError('INVALID_ITS_ID', 'Invalid ITS ID');
  return value;
}

@ApiTags('users')
@ApiBearerAuth()
@Controller({ path: 'users', version: API_V1 })
export class UsersController {
  constructor(private readonly service: UsersService) {}

  @Post('sync')
  @RequireScopes('FEDERATION')
  @ApiOperation({ summary: 'Create or update a user profile from Identity Federation (never credentials)' })
  sync(@Body() dto: SyncUserDto) {
    return this.service.sync(dto);
  }

  @Get(':itsId')
  @RequirePermission('USER_MGMT', 'view')
  @ApiOperation({ summary: 'User profile with role assignments (filtered to your workspace)' })
  get(@Actor() actor: ActorContext, @Param('itsId') id: string) {
    return this.service.get(actor, itsId(id));
  }

  @Get(':itsId/roles')
  @RequirePermission('USER_MGMT', 'view')
  roles(@Actor() actor: ActorContext, @Param('itsId') id: string) {
    return this.service.listRoles(actor, itsId(id));
  }

  @Post()
  @RequirePermission('USER_MGMT', 'create')
  create(@Actor() actor: ActorContext, @Body() dto: CreateUserDto) {
    return this.service.create(actor, dto);
  }

  @Patch(':itsId')
  @RequirePermission('USER_MGMT', 'edit')
  update(@Actor() actor: ActorContext, @Param('itsId') id: string, @Body() dto: UpdateUserDto) {
    return this.service.update(actor, itsId(id), dto);
  }
}

@ApiTags('users')
@ApiBearerAuth()
@Controller({ path: 'user-roles', version: API_V1 })
export class UserRolesController {
  constructor(private readonly service: UsersService) {}

  @Post()
  @RequirePermission('USER_MGMT', 'create')
  @ApiOperation({ summary: 'Assign a role to a user in a scope (CORE | BUSINESS_UNIT bu_id | UTILITY utility_id)' })
  assign(@Actor() actor: ActorContext, @Body() dto: UserRoleDto) {
    return this.service.assign(actor, dto);
  }

  @Delete()
  @HttpCode(200)
  @RequirePermission('USER_MGMT', 'edit')
  @ApiOperation({ summary: 'Revoke a role assignment' })
  revoke(@Actor() actor: ActorContext, @Body() dto: UserRoleDto) {
    return this.service.revoke(actor, dto);
  }
}
