import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { Actor, RequireCoreScope, RequirePermission } from '@common/decorators/rbac.decorators';
import { ActorContext } from '@shared/types/principal.types';
import { ApplicationsService } from '../services/applications.service';
import { ApplicationQueryDto, CreateApplicationDto } from './dto/application.dto';

@ApiTags('applications')
@ApiBearerAuth()
@Controller({ path: 'applications', version: API_V1 })
export class ApplicationsController {
  constructor(private readonly service: ApplicationsService) {}

  @Get()
  @RequirePermission('CONFIGURATION', 'view')
  list(@Actor() actor: ActorContext, @Query() query: ApplicationQueryDto) {
    return this.service.list(actor, query.status);
  }

  @Post()
  @RequirePermission('CONFIGURATION', 'edit')
  @RequireCoreScope()
  create(@Actor() actor: ActorContext, @Body() dto: CreateApplicationDto) {
    return this.service.create(actor, dto);
  }
}
