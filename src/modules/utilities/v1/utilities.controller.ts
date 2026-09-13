import { Body, Controller, Get, Param, ParseUUIDPipe, Patch, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { Actor, RequirePermission } from '@common/decorators/rbac.decorators';
import { ActorContext } from '@shared/types/principal.types';
import { UtilitiesService } from '../services/utilities.service';
import { CreateUtilityDto, UpdateUtilityDto, UtilityQueryDto } from './dto/utility.dto';

@ApiTags('utilities')
@ApiBearerAuth()
@Controller({ path: 'utilities', version: API_V1 })
export class UtilitiesController {
  constructor(private readonly service: UtilitiesService) {}

  @Get()
  @RequirePermission('UTILITY_MGMT', 'view')
  list(@Actor() actor: ActorContext, @Query() query: UtilityQueryDto) {
    return this.service.list(actor, query);
  }

  @Post()
  @RequirePermission('UTILITY_MGMT', 'create')
  create(@Actor() actor: ActorContext, @Body() dto: CreateUtilityDto) {
    return this.service.create(actor, dto);
  }

  @Patch(':utilityId')
  @RequirePermission('UTILITY_MGMT', 'edit')
  update(@Actor() actor: ActorContext, @Param('utilityId', new ParseUUIDPipe()) utilityId: string, @Body() dto: UpdateUtilityDto) {
    return this.service.update(actor, utilityId, dto);
  }
}
