import { Body, Controller, Get, HttpCode, Logger, Post, Req, Res } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { API_V1 } from '@common/constants/api-version.constants';
import { Public } from '@common/decorators/public.decorator';
import { DomainError } from '@common/errors/domain-error';
import { AuditService } from '@core/audit/audit.service';
import { AssertionVerificationError, AssertionVerifierService } from '../services/assertion-verifier.service';
import { LocalSessionService, MiqaatCoreRole, type SessionFailureReason } from '../services/local-session.service';
import { bindingContextOf } from '@common/security/session-binding';
import { decideSessionPermission } from '../services/session-permission';
import { CheckSessionPermissionDto } from './dto/check-session-permission.dto';
import { SelectRoleDto } from './dto/select-role.dto';
import { VerifyAssertionDto } from './dto/verify-assertion.dto';

const COOKIE_NAME = 'miqaat_session';

/**
 * Every session-based refusal in this controller goes through here, so `miqaat_session` and the
 * pending-selection token cannot end up with different status codes, messages or log shapes.
 * The response deliberately states only that re-authentication is needed: telling a caller whether a
 * token was expired, revoked or simply bound to another IP would confirm the token exists.
 */
function sessionRefused(_reason: SessionFailureReason): DomainError {
  return new DomainError('SESSION_REQUIRED', 'Your session is no longer valid. Please sign in again.', 401);
}
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
    const selection = await this.sessions.consumePendingSelection(dto.pending_token, bindingContextOf(req));
    if (!selection.ok) {
      this.logger.warn({ msg: 'role selection rejected', reason: selection.reason, ...(selection.audit ?? {}) });
      await this.audit.record({ eventType: 'LOCAL_SESSION_SELECTION_REJECTED', decision: 'DENY', reason: selection.reason, metadata: selection.audit });
      throw sessionRefused(selection.reason);
    }
    const pending = selection.pending;

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
  @ApiOperation({ summary: 'Resolve the current local session from its cookie (same IP + User-Agent as at login)' })
  async me(@Req() req: FastifyRequest) {
    const resolved = await this.resolveFromCookie(req, 'SESSION_ME');
    return { verified: true, ...(await presentSession(this.sessions, resolved)) };
  }

  /**
   * Read cookie -> resolve with the current request's IP + User-Agent -> allow only on a full match.
   * The one place this controller turns a cookie into a session; `/me` and `/logout` both use it so
   * neither can accidentally skip a step.
   */
  private async resolveFromCookie(req: FastifyRequest, eventType: string) {
    const token = readCookie(req, COOKIE_NAME);
    if (!token) {
      await this.audit.record({ eventType, decision: 'DENY', reason: 'NO_COOKIE' });
      throw sessionRefused('NOT_FOUND');
    }
    const ctx = bindingContextOf(req);
    const result = await this.sessions.resolveSession(token, ctx);
    if (!result.ok) {
      this.logger.warn({ msg: 'session rejected', event: eventType, reason: result.reason, ...(result.audit ?? {}) });
      await this.audit.record({ eventType, decision: 'DENY', reason: result.reason, metadata: result.audit });
      throw sessionRefused(result.reason);
    }
    return result.session;
  }

  /**
   * Server-side enforcement for a Business Unit / Admin Panel backend: may the user behind this session
   * perform `action` on `module` (optionally inside `tenant_id`)? Decided on the live RBAC rows, so changes
   * made after sign-in apply immediately. 200 when allowed, 403 PERMISSION_DENIED otherwise.
   */
  @Post('check')
  @HttpCode(200)
  @Public()
  @ApiOperation({ summary: 'Enforce a module action (and tenant) for the current local session: 200 allowed, 403 denied' })
  async check(@Body() dto: CheckSessionPermissionDto, @Req() req: FastifyRequest) {
    const session = await this.resolveFromCookie(req, 'SESSION_PERMISSION_CHECK');
    const { permissions } = await this.sessions.getModulePermissions(session.role.roleId, session.role.roleLevel);
    const decision = decideSessionPermission(
      {
        userStatus: session.user.status,
        roleStatus: session.roleStatus,
        roleLevel: session.role.roleLevel,
        roleTenantId: session.role.tenantId,
        tenantStatus: session.tenantStatus,
        permissions,
      },
      { module: dto.module, action: dto.action, tenantId: dto.tenant_id ?? null },
    );
    const resource = { module: dto.module.toUpperCase(), action: dto.action.toUpperCase(), tenant_id: dto.tenant_id ?? session.role.tenantId };
    if (!decision.allowed) {
      await this.audit.record({
        eventType: 'SESSION_PERMISSION_CHECK',
        itsId: session.user.itsId,
        resourceType: 'module_action',
        resourceId: `${resource.module}:${resource.action}`,
        decision: 'DENY',
        reason: decision.reason,
        metadata: { role_code: session.role.roleCode, tenant_id: resource.tenant_id },
      });
      throw new DomainError('PERMISSION_DENIED', 'You do not have permission to perform this action', 403, { reason: decision.reason });
    }
    return { allowed: true, its_id: session.user.itsId, role: session.role.roleCode, ...resource };
  }

  @Post('logout')
  @HttpCode(200)
  @Public()
  @ApiOperation({ summary: 'Revoke the current local session' })
  async logout(@Req() req: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    // Bound like every other session endpoint: a caller that cannot prove the session is theirs may not
    // revoke it, so a leaked cookie cannot be used to force someone else's session closed.
    const session = await this.resolveFromCookie(req, 'SESSION_LOGOUT');
    await this.sessions.revokeSession(session.sessionToken);
    clearSessionCookie(reply);
    await this.audit.record({ eventType: 'LOCAL_SESSION_REVOKED', itsId: session.user.itsId, decision: 'ALLOW', reason: 'USER_LOGOUT' });
    return { logged_out: true };
  }
}
