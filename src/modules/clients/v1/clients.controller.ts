import { Body, Controller, Delete, Get, Param, Patch, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { URI_TYPES, UriType } from '@common/constants/client.constants';
import { CLIENT_ID } from '@common/constants/validation.constants';
import { RequireCoreScope, RequirePermission } from '@common/decorators/rbac.decorators';
import { DomainError } from '@common/errors/domain-error';
import { ClientsService } from '../services/clients.service';
import { AddCallbackDto } from './dto/add-callback.dto';
import { AddOriginDto } from './dto/add-origin.dto';
import { ClientQueryDto } from './dto/client-query.dto';
import { CreateClientDto } from './dto/create-client.dto';
import { RemoveCallbackDto } from './dto/remove-callback.dto';
import { RemoveOriginDto } from './dto/remove-origin.dto';
import { UpdateClientDto } from './dto/update-client.dto';

function validClientId(clientId: string): string {
  if (!CLIENT_ID.test(clientId)) throw new DomainError('INVALID_CLIENT_ID', 'Invalid client ID');
  return clientId;
}

/** Federation client registry: CONFIGURATION view to read; changes require a CORE workspace. */
@ApiTags('clients')
@ApiBearerAuth()
@Controller({ path: 'clients', version: API_V1 })
export class ClientsController {
  constructor(private readonly service: ClientsService) {}

  @Get()
  @RequirePermission('CONFIGURATION', 'view')
  list(@Query() query: ClientQueryDto) {
    return this.service.list(query);
  }

  @Post()
  @RequirePermission('CONFIGURATION', 'edit')
  @RequireCoreScope()
  @ApiOperation({ summary: 'Register a client (always starts in PENDING)' })
  create(@Body() dto: CreateClientDto) {
    return this.service.create(dto);
  }

  @Get(':clientId')
  @RequirePermission('CONFIGURATION', 'view')
  get(@Param('clientId') clientId: string) {
    return this.service.getConfig(validClientId(clientId));
  }

  @Patch(':clientId')
  @RequirePermission('CONFIGURATION', 'edit')
  @RequireCoreScope()
  @ApiOperation({ summary: 'Update client settings or move it through its lifecycle' })
  update(@Param('clientId') clientId: string, @Body() dto: UpdateClientDto) {
    return this.service.update(validClientId(clientId), dto);
  }

  @Get(':clientId/origins')
  @RequirePermission('CONFIGURATION', 'view')
  @ApiOperation({ summary: 'List the embed origins allowed to frame the login page for this client' })
  origins(@Param('clientId') clientId: string) {
    return this.service.listOrigins(validClientId(clientId));
  }

  @Post(':clientId/origins')
  @RequirePermission('CONFIGURATION', 'edit')
  @RequireCoreScope()
  @ApiOperation({ summary: 'Allow an embed origin (exact scheme://host[:port], https; http only for localhost in dev). Idempotent.' })
  addOrigin(@Param('clientId') clientId: string, @Body() dto: AddOriginDto) {
    return this.service.addOrigin(validClientId(clientId), dto.origin);
  }

  @Delete(':clientId/origins')
  @RequirePermission('CONFIGURATION', 'edit')
  @RequireCoreScope()
  @ApiOperation({ summary: 'Remove an embed origin: ?origin=<origin> or JSON body { "origin": "..." }' })
  @ApiQuery({ name: 'origin', required: false })
  removeOrigin(@Param('clientId') clientId: string, @Query('origin') origin: string | undefined, @Body() dto: RemoveOriginDto) {
    return this.service.removeOrigin(validClientId(clientId), origin ?? dto?.origin ?? '');
  }

  @Get(':clientId/callbacks')
  @RequirePermission('CONFIGURATION', 'view')
  callbacks(@Param('clientId') clientId: string) {
    return this.service.listCallbacks(validClientId(clientId));
  }

  @Post(':clientId/callbacks')
  @RequirePermission('CONFIGURATION', 'edit')
  @RequireCoreScope()
  @ApiOperation({ summary: 'Add a CALLBACK, POST_LOGOUT_REDIRECT or BACK_CHANNEL_LOGOUT URI (exact match)' })
  addCallback(@Param('clientId') clientId: string, @Body() dto: AddCallbackDto) {
    return this.service.addCallback(validClientId(clientId), dto);
  }

  @Delete(':clientId/callbacks')
  @RequirePermission('CONFIGURATION', 'edit')
  @RequireCoreScope()
  @ApiOperation({ summary: 'Remove a callback / logout URI: ?uri=&uri_type= or JSON body { "uri", "uri_type" }' })
  @ApiQuery({ name: 'uri', required: false })
  @ApiQuery({ name: 'uri_type', enum: URI_TYPES, required: false })
  removeCallback(
    @Param('clientId') clientId: string,
    @Query('uri') uri: string | undefined,
    @Query('uri_type') uriType: UriType | undefined,
    @Body() dto: RemoveCallbackDto,
  ) {
    const type = uriType ?? dto?.uri_type ?? 'CALLBACK';
    if (!URI_TYPES.includes(type)) throw new DomainError('INVALID_URI_TYPE', 'Invalid uri_type');
    return this.service.removeCallback(validClientId(clientId), uri ?? dto?.uri ?? '', type);
  }
}
