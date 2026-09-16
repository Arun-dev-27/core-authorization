import { Body, Controller, Get, HttpCode, Logger, Post, Req, Res } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { API_V1 } from '@common/constants/api-version.constants';
import { Public } from '@common/decorators/public.decorator';
import { DomainError } from '@common/errors/domain-error';
import { AuditService } from '@core/audit/audit.service';
import { AssertionVerificationError, AssertionVerifierService } from '../services/assertion-verifier.service';
import { LocalSessionService, MiqaatCoreRole } from '../services/local-session.service';
import { SelectRoleDto } from './dto/select-role.dto';
import { VerifyAssertionDto } from './dto/verify-assertion.dto';

const COOKIE_NAME = 'miqaat_session';
const SESSION_TTL_SECONDS = 8 * 3600;

function readCookie(req: FastifyRequest, name: string): string | undefined {
  const header = req.headers.cookie;
  if (typeof header !== 'string') return undefined;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    if (part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return undefined;
}

/**
 * SameSite=None + Secure is required for a cross-origin cookie (frontend on :5175, this service on :3002).
 * Secure cookies work over plain http on localhost specifically - Chrome treats localhost as a secure
 * context regardless of scheme. A real deployment puts both behind TLS, where this needs no change.
 */
function setSessionCookie(reply: FastifyReply, token: string, maxAgeSeconds: number): void {
  reply.header('set-cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAgeSeconds}`);
}

function clearSessionCookie(reply: FastifyReply): void {
  reply.header('set-cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`);
}

async function presentSession(
  sessions: LocalSessionService,
  session: {
    user: { itsId: string; name: string; email: string; status: string };
    role: { roleId: string; roleCode: string; roleName: string; roleLevel: 'CORE_ADMIN' | 'BUSINESS_UNIT_ADMIN' | 'UTILITY_ADMIN'; tenantId: string | null; tenantName: string | null };
  },
) {
  const { modules, permissions } = await sessions.getModulePermissions(session.role.roleId, session.role.roleLevel);
  return {
    its_id: session.user.itsId,
    name: session.user.name,
    email: session.user.email,
    status: session.user.status,
    role: { code: session.role.roleCode, name: session.role.roleName, level: session.role.roleLevel, tenant_id: session.role.tenantId, tenant_name: session.role.tenantName },
    modules,
    permissions,
  };
}

/** One card on the "Where do you want to log in?" screen. */
function presentRoleOption(role: MiqaatCoreRole) {
  return { role_id: role.roleId, role_code: role.roleCode, role_name: role.roleName, role_level: role.roleLevel, tenant_id: role.tenantId, tenant_name: role.tenantName };
}

/**
 * Public: called directly from a Business Unit's browser, right after core-authentication hands the
 * core_assertion back via postMessage. Verifies it against core-authentication's JWKS, then establishes
 * a local, stateful session in miqaat_core.user_sessions (opaque cookie - deliberately not another JWT,
 * so it can be revoked by deleting/marking the row, unlike the stateless authorization_token in
 * authorization.controller.ts).
 */
@ApiTags('authorization')
@Controller({ path: 'authorization/session', version: API_V1 })
export class SessionController {
  private readonly logger = new Logger(SessionController.name);

  constructor(
    private readonly verifier: AssertionVerifierService,
    private readonly sessions: LocalSessionService,
    private readonly audit: AuditService,
  ) {}

  @Post()
  @HttpCode(200)
  @Public()
  @ApiOperation({ summary: 'Verify a core_assertion, establish a local miqaat_core session, and set its cookie' })
  async login(@Body() dto: VerifyAssertionDto, @Req() req: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    try {
      const verified = await this.verifier.verify(dto.core_assertion);
      this.logger.log({ msg: 'core assertion verified', its_id: verified.itsId, client_id: verified.clientId, sid: verified.sid, jti: verified.jti });
      await this.audit.record({
        eventType: 'FEDERATION_ASSERTION_VERIFIED',
        itsId: verified.itsId,
        clientId: verified.clientId,
        decision: 'ALLOW',
        metadata: { sid: verified.sid, jti: verified.jti, txn: verified.transactionId, auth_time: verified.authTime },
      });

      const user = await this.sessions.findUserByItsId(verified.itsId);
      if (!user) throw new DomainError('USER_NOT_ONBOARDED', 'This ITS ID is not onboarded to the Core Admin Panel', 403);
      if (user.status === 'DISABLED') throw new DomainError('USER_DISABLED', 'This account is disabled', 403);

      const ipAddress = req.ip ?? null;
      const userAgent = (req.headers['user-agent'] as string) ?? null;

      const roles = await this.sessions.listRolesForUser(user.id);
      if (roles.length === 0) throw new DomainError('NO_ROLE_ASSIGNED', 'This user holds no active role', 403);

      if (roles.length > 1) {
        const { pendingToken } = await this.sessions.createPendingSelection({
          userId: user.id,
          itsId: user.itsId,
          coreSid: verified.sid,
          aud: verified.clientId,
          ipAddress,
          userAgent,
        });
        await this.audit.record({ eventType: 'LOCAL_SESSION_SELECTION_REQUIRED', itsId: user.itsId, clientId: verified.clientId, decision: 'ALLOW', metadata: { role_count: roles.length } });
        return { verified: true, selection_required: true, pending_token: pendingToken, its_id: user.itsId, name: user.name, roles: roles.map(presentRoleOption) };
      }

      const role = roles[0];
      const { sessionToken } = await this.sessions.createSession({
        userId: user.id,
        roleId: role.roleId,
        coreSid: verified.sid,
        aud: verified.clientId,
        ipAddress,
        userAgent,
      });
      await this.sessions.recordLogin(user.id);
      setSessionCookie(reply, sessionToken, SESSION_TTL_SECONDS);

      await this.audit.record({ eventType: 'LOCAL_SESSION_CREATED', itsId: user.itsId, clientId: verified.clientId, decision: 'ALLOW', metadata: { role_code: role.roleCode } });
      return { verified: true, ...(await presentSession(this.sessions, { user, role })) };
    } catch (error) {
      const reason = error instanceof AssertionVerificationError ? error.reason : error instanceof DomainError ? error.code : 'VERIFICATION_ERROR';
      this.logger.warn({ msg: 'session login rejected', reason, ip: req.ip });
      await this.audit.record({ eventType: 'FEDERATION_ASSERTION_REJECTED', decision: 'DENY', reason });
      throw error;
    }
  }

  @Post('select')
  @HttpCode(200)
  @Public()
  @ApiOperation({ summary: 'Finalize a multi-role login: pick which role/tenant to establish the local session as' })
  async select(@Body() dto: SelectRoleDto, @Req() req: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    const pending = await this.sessions.consumePendingSelection(dto.pending_token);
    if (!pending) throw new DomainError('SELECTION_EXPIRED', 'This role selection has expired; sign in again', 401);

    const role = await this.sessions.findRoleForUser(pending.userId, dto.role_id);
    if (!role) throw new DomainError('ROLE_NOT_ASSIGNED', 'That role is no longer assigned to you', 403);

    const user = await this.sessions.findUserByItsId(pending.itsId);
    if (!user) throw new DomainError('USER_NOT_ONBOARDED', 'This ITS ID is not onboarded to the Core Admin Panel', 403);

    const { sessionToken } = await this.sessions.createSession({
      userId: pending.userId,
      roleId: role.roleId,
      coreSid: pending.coreSid,
      aud: pending.aud,
      ipAddress: pending.ipAddress,
      userAgent: pending.userAgent,
    });
    await this.sessions.recordLogin(pending.userId);
    setSessionCookie(reply, sessionToken, SESSION_TTL_SECONDS);

    await this.audit.record({ eventType: 'LOCAL_SESSION_CREATED', itsId: pending.itsId, clientId: pending.aud, decision: 'ALLOW', metadata: { role_code: role.roleCode } });
    return { verified: true, ...(await presentSession(this.sessions, { user, role })) };
  }

  @Get('me')
  @Public()
  @ApiOperation({ summary: 'Resolve the current local session from its cookie' })
  async me(@Req() req: FastifyRequest) {
    const token = readCookie(req, COOKIE_NAME);
    const session = token ? await this.sessions.resolveSession(token) : null;
    if (!session) throw new DomainError('SESSION_REQUIRED', 'No active session', 401);
    return { verified: true, ...(await presentSession(this.sessions, session)) };
  }

  @Post('logout')
  @HttpCode(200)
  @Public()
  @ApiOperation({ summary: 'Revoke the current local session' })
  async logout(@Req() req: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    const token = readCookie(req, COOKIE_NAME);
    if (token) await this.sessions.revokeSession(token);
    clearSessionCookie(reply);
    return { logged_out: true };
  }
}
