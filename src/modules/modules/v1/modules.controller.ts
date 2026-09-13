import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { RequireCoreScope, RequirePermission } from '@common/decorators/rbac.decorators';
import { ModulesService } from '../services/modules.service';
import { CreateModuleDto, CreatePermissionDto, ModuleQueryDto, PermissionQueryDto } from './dto/module.dto';

@ApiTags('modules')
@ApiBearerAuth()
@Controller({ path: 'modules', version: API_V1 })
export class ModulesController {
  constructor(private readonly service: ModulesService) {}

  @Get()
  @RequirePermission('ROLE_MGMT', 'view')
  @ApiOperation({ summary: 'Modules with their permissions (14 defaults + application modules)' })
  list(@Query() query: ModuleQueryDto) {
    return this.service.listModules(query);
  }

  @Post()
  @RequirePermission('ROLE_MGMT', 'create')
  @RequireCoreScope()
  @ApiOperation({ summary: 'Add a custom module (is_default = false) and its permissions' })
  create(@Body() dto: CreateModuleDto) {
    return this.service.createModule(dto);
  }
}

@ApiTags('permissions')
@ApiBearerAuth()
@Controller({ path: 'permissions', version: API_V1 })
export class PermissionsController {
  constructor(private readonly service: ModulesService) {}

  @Get()
  @RequirePermission('ROLE_MGMT', 'view')
  list(@Query() query: PermissionQueryDto) {
    return this.service.listPermissions(query);
  }

  @Post()
  @RequirePermission('ROLE_MGMT', 'create')
  @RequireCoreScope()
  @ApiOperation({ summary: 'Add an action to a module; permission_code = <MODULE_CODE>_<ACTION>' })
  create(@Body() dto: CreatePermissionDto) {
    return this.service.createPermission(dto);
  }
}
