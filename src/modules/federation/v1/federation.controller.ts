import { Body, Controller, Get, HttpCode, Param, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { CLIENT_ID, ENVIRONMENT_CODE, ITS_ID } from '@common/constants/validation.constants';
import { RequireScopes } from '@common/decorators/require-scopes.decorator';
import { DomainError } from '@common/errors/domain-error';
import { SessionRevocationService } from '@modules/auth/services/session-revocation.service';
import { ClientsService } from '@modules/clients/services/clients.service';
import { FederationDirectoryService } from '../services/federation-directory.service';
import { LocalSessionService } from '../services/local-session.service';
import { CORE_SID, RecordSessionDto } from './dto/record-session.dto';
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
    private readonly revocation: SessionRevocationService,
    private readonly localSessions: LocalSessionService,
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

  /**
   * A user signed in and selected a workspace. The session is recorded in the Core Admin Control Panel
   * model (miqaat_core.user_sessions) so it has the durable history its data model calls for; no password,
   * assertion or token is stored, only a hash and the federation sid.
   */
  @Post('sessions')
  @HttpCode(201)
  @RequireScopes('FEDERATION')
  @ApiOperation({ summary: 'Record a signed-in session (miqaat_core.user_sessions) for a selected workspace' })
  recordSession(@Body() dto: RecordSessionDto) {
    return this.localSessions.record(dto);
  }

  /**
   * Identity ended a session (logout, sign-out everywhere, administrator force logout, user switch,
   * re-authentication). Access tokens carrying this sid are refused here from now on, until they expire,
   * and every local session recorded under it is marked revoked.
   */
  @Post('sessions/:sid/revoke')
  @HttpCode(200)
  @RequireScopes('FEDERATION')
  @ApiOperation({ summary: 'Mark an Identity session as signed out, so its access tokens stop working here too' })
  async revokeSession(@Param('sid') sid: string) {
    if (!CORE_SID.test(sid)) throw new DomainError('INVALID_SID', 'Invalid session id');
    const revoked = await this.revocation.revoke(sid);
    return { ...revoked, local_sessions_revoked: await this.localSessions.revokeByCoreSid(sid) };
  }
}
