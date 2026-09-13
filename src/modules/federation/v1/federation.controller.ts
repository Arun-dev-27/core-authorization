import { Body, Controller, Get, HttpCode, Param, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { CLIENT_ID, ENVIRONMENT_CODE, ITS_ID } from '@common/constants/validation.constants';
import { RequireScopes } from '@common/decorators/require-scopes.decorator';
import { DomainError } from '@common/errors/domain-error';
import { ClientsService } from '@modules/clients/services/clients.service';
import { FederationDirectoryService } from '../services/federation-directory.service';
import { ResolveAssignmentDto } from './dto/resolve-assignment.dto';

/**
 * Internal, service-to-service API consumed only by Identity Federation (service token with FEDERATION scope).
 * Client configuration for login validation, and workspace data for the Core Portal login / select-scope flow.
 */
@ApiTags('internal-federation')
@ApiBearerAuth()
@Controller({ path: 'internal/federation', version: API_V1 })
export class FederationController {
  constructor(
    private readonly clients: ClientsService,
    private readonly directory: FederationDirectoryService,
  ) {}

  @Get('clients/:clientId')
  @RequireScopes('FEDERATION')
  @ApiOperation({ summary: 'Client configuration used by Identity Federation to validate embedded login' })
  client(@Param('clientId') clientId: string) {
    if (!CLIENT_ID.test(clientId)) throw new DomainError('INVALID_CLIENT_ID', 'Invalid client ID');
    return this.clients.getConfig(clientId);
  }

  @Get('users/:itsId/assignments')
  @RequireScopes('FEDERATION')
  @ApiOperation({ summary: 'Workspaces (role × scope) returned by POST /login' })
  assignments(@Param('itsId') itsId: string) {
    if (!ITS_ID.test(itsId)) throw new DomainError('INVALID_ITS_ID', 'Invalid ITS ID');
    return this.directory.assignments(itsId);
  }

  @Post('assignments/resolve')
  @HttpCode(200)
  @RequireScopes('FEDERATION')
  @ApiOperation({ summary: 'Validate a workspace for POST /select-scope; returns active scope + permission map' })
  resolve(@Body() dto: ResolveAssignmentDto) {
    return this.directory.resolve(dto);
  }

  @Get('users/:itsId/applications')
  @RequireScopes('FEDERATION')
  @ApiQuery({ name: 'environment', example: 'DEV' })
  @ApiOperation({ summary: 'Applications a user may launch from the Core Portal' })
  applications(@Param('itsId') itsId: string, @Query('environment') environment: string) {
    if (!ITS_ID.test(itsId)) throw new DomainError('INVALID_ITS_ID', 'Invalid ITS ID');
    if (!ENVIRONMENT_CODE.test(environment ?? '')) throw new DomainError('INVALID_ENVIRONMENT', 'environment is required');
    return this.directory.launchableApplications(itsId, environment);
  }
}
