import { Body, Controller, Get, Param, ParseUUIDPipe, Patch, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { RequireCoreScope, RequirePermission } from '@common/decorators/rbac.decorators';
import { TenantsService } from '../services/tenants.service';
import { CreateTenantDto, UpdateTenantDto } from './dto/tenant.dto';

@ApiTags('tenants')
@ApiBearerAuth()
@Controller({ path: 'tenants', version: API_V1 })
export class TenantsController {
  constructor(private readonly service: TenantsService) {}

  @Get()
  @RequirePermission('BUSINESS_UNIT_MGMT', 'view')
  @RequireCoreScope()
  list() {
    return this.service.list();
  }

  @Post()
  @RequirePermission('BUSINESS_UNIT_MGMT', 'create')
  @RequireCoreScope()
  @ApiOperation({ summary: 'Create a tenant (Platform Administrator)' })
  create(@Body() dto: CreateTenantDto) {
    return this.service.create(dto);
  }

  @Patch(':tenantId')
  @RequirePermission('BUSINESS_UNIT_MGMT', 'edit')
  @RequireCoreScope()
  update(@Param('tenantId', new ParseUUIDPipe()) tenantId: string, @Body() dto: UpdateTenantDto) {
    return this.service.update(tenantId, dto);
  }
}
