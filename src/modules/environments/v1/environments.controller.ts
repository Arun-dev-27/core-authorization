import { Body, Controller, Get, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { RequireCoreScope, RequirePermission } from '@common/decorators/rbac.decorators';
import { EnvironmentsService } from '../services/environments.service';
import { CreateEnvironmentDto } from './dto/create-environment.dto';

@ApiTags('environments')
@ApiBearerAuth()
@Controller({ path: 'environments', version: API_V1 })
export class EnvironmentsController {
  constructor(private readonly service: EnvironmentsService) {}

  @Get()
  @RequirePermission('CONFIGURATION', 'view')
  list() {
    return this.service.list();
  }

  @Post()
  @RequirePermission('CONFIGURATION', 'edit')
  @RequireCoreScope()
  create(@Body() dto: CreateEnvironmentDto) {
    return this.service.create(dto);
  }
}
