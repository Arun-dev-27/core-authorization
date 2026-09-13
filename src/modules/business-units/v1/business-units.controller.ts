import { Body, Controller, Get, Param, ParseUUIDPipe, Patch, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { Actor, RequirePermission } from '@common/decorators/rbac.decorators';
import { ActorContext } from '@shared/types/principal.types';
import { BusinessUnitsService } from '../services/business-units.service';
import { BusinessUnitQueryDto, CreateBusinessUnitDto, UpdateBusinessUnitDto } from './dto/business-unit.dto';

@ApiTags('business-units')
@ApiBearerAuth()
@Controller({ path: 'business-units', version: API_V1 })
export class BusinessUnitsController {
  constructor(private readonly service: BusinessUnitsService) {}

  @Get()
  @RequirePermission('BUSINESS_UNIT_MGMT', 'view')
  list(@Actor() actor: ActorContext, @Query() query: BusinessUnitQueryDto) {
    return this.service.list(actor, query.status);
  }

  @Post()
  @RequirePermission('BUSINESS_UNIT_MGMT', 'create')
  create(@Actor() actor: ActorContext, @Body() dto: CreateBusinessUnitDto) {
    return this.service.create(actor, dto);
  }

  @Patch(':buId')
  @RequirePermission('BUSINESS_UNIT_MGMT', 'edit')
  update(@Actor() actor: ActorContext, @Param('buId', new ParseUUIDPipe()) buId: string, @Body() dto: UpdateBusinessUnitDto) {
    return this.service.update(actor, buId, dto);
  }
}
