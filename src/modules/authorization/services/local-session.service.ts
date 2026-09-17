import { randomBytes } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import type Redis from 'ioredis';
import { REDIS } from '@core/cache/redis.module';
import type { RoleLevel } from '@core/database/entities/admin/admin-rbac.enums';
import type { AdminUser } from '@core/database/entities/admin/admin-user.entity';
import type { Role } from '@core/database/entities/admin/role.entity';
import { AdminRbacRepository } from '@core/database/repositories/admin-rbac.repository';
import {
  bindingAuditMetadata,
  checkSessionBinding,
  type SessionBindingContext,
  type SessionBindingFailure,
} from '@common/security/session-binding';

export interface MiqaatCoreUser {
  id: string;
  itsId: string;
  name: string;
  email: string;
  status: 'INVITED' | 'ACTIVE' | 'DISABLED';
}

export interface MiqaatCoreRole {
  roleId: string;
  roleCode: string;
  roleName: string;
  roleLevel: RoleLevel;
  tenantId: string | null;
  tenantName: string | null;
}

export interface LocalSession {
  sessionToken: string;
  expiresAt: Date;
  user: MiqaatCoreUser;
  role: MiqaatCoreRole;
  /** Current roles.status and tenants.status (null for the tenant-less CORE_ADMIN role), read with the session. */
  roleStatus: string;
  tenantStatus: string | null;
}

/** Why a cookie did not yield a session. Used verbatim as the failure reason in the masked audit log. */
export type SessionFailureReason = 'INVALID_TOKEN' | 'NOT_FOUND' | 'REVOKED' | 'EXPIRED' | SessionBindingFailure;

export type SessionResolution =
  | { ok: true; session: LocalSession }
  | { ok: false; reason: SessionFailureReason; audit?: Record<string, unknown> };

export type PendingSelectionResolution =
  | { ok: true; pending: PendingSelection }
  | { ok: false; reason: SessionFailureReason; audit?: Record<string, unknown> };

export interface PendingSelection {
  userId: string;
  itsId: string;
  coreSid: string | null;
  aud: string | null;
  ipAddress: string | null;
  userAgent: string | null;
}

const SESSION_TTL_SECONDS = 8 * 3600;
const PENDING_SELECTION_TTL_SECONDS = 5 * 60;
const PENDING_SELECTION_KEY_PREFIX = 'authz:pending-login:';

function toUser(user: AdminUser): MiqaatCoreUser {
  return { id: user.id, itsId: user.itsId ?? '', name: user.name, email: user.email, status: user.status };
}

function toRole(role: Role): MiqaatCoreRole {
  return { roleId: role.id, roleCode: role.roleCode, roleName: role.name, roleLevel: role.roleLevel, tenantId: role.tenantId, tenantName: role.tenant?.name ?? null };
}

/** Platform-wide role first, then by tenant name, then role name - a stable order for the role picker. */
function byScope(a: MiqaatCoreRole, b: MiqaatCoreRole): number {
  if ((a.tenantName === null) !== (b.tenantName === null)) return a.tenantName === null ? -1 : 1;
  return (a.tenantName ?? '').localeCompare(b.tenantName ?? '') || a.roleName.localeCompare(b.roleName);
}

/**
 * The Core Admin Control Panel's local session over the EXISTING admin_db RBAC tables, through AdminRbacRepository
 * (TypeORM entities AdminUser, UserRole, Role, Tenant, RolePermission, ModuleAction, CoreModule, PermissionAction,
 * UserSession). Never creates users, roles, tenants, modules or assignments.
 */
@Injectable()
export class LocalSessionService {
  constructor(
    private readonly rbac: AdminRbacRepository,
    @Inject(REDIS) private readonly redis: Redis,
  ) {}

  async findUserByItsId(itsId: string): Promise<MiqaatCoreUser | null> {
    const user = await this.rbac.findUserByItsId(itsId);
    return user ? toUser(user) : null;
  }

  /**
   * Every role this user currently holds (tenant scoped, or the one platform-wide CORE_ADMIN role). A user holding
   * more than one must pick which to act as - see SessionController's "Where do you want to log in?" step.
   */
  async listRolesForUser(userId: string): Promise<MiqaatCoreRole[]> {
    const assignments = await this.rbac.findActiveAssignments(userId);
    return assignments.map((a) => toRole(a.role)).sort(byScope);
  }

  /** Re-validates a chosen role_id still belongs to this user at selection time (roles can change between the two calls). */
  async findRoleForUser(userId: string, roleId: string): Promise<MiqaatCoreRole | null> {
    const [assignment] = await this.rbac.findActiveAssignments(userId, roleId);
    return assignment ? toRole(assignment.role) : null;
  }

  /**
   * Holds "assertion verified, awaiting role selection" between the two calls a multi-role login needs.
   * Short-lived and one-time (deleted on `consumePendingSelection`) - the `core_assertion` itself can't be
   * resubmitted for step two, its `jti` is already burned by `AssertionVerifierService`.
   */
  async createPendingSelection(input: PendingSelection): Promise<{ pendingToken: string; roles: MiqaatCoreRole[] }> {
    const roles = await this.listRolesForUser(input.userId);
    const pendingToken = randomBytes(32).toString('base64url');
    await this.redis.set(`${PENDING_SELECTION_KEY_PREFIX}${pendingToken}`, JSON.stringify(input), 'EX', PENDING_SELECTION_TTL_SECONDS);
    return { pendingToken, roles };
  }

  /** Step two of a multi-role login carries a session, so it is bound exactly like a cookie is. */
  async consumePendingSelection(pendingToken: string, ctx: SessionBindingContext): Promise<PendingSelectionResolution> {
    if (typeof pendingToken !== 'string' || pendingToken.length < 16 || pendingToken.length > 128) {
      return { ok: false, reason: 'INVALID_TOKEN' };
    }
    const key = `${PENDING_SELECTION_KEY_PREFIX}${pendingToken}`;
    const raw = await this.redis.get(key);
    if (!raw) return { ok: false, reason: 'NOT_FOUND' };
    const pending = JSON.parse(raw) as PendingSelection;

    const stored = { ipAddress: pending.ipAddress, userAgent: pending.userAgent };
    const binding = checkSessionBinding(stored, ctx);
    if (!binding.ok) {
      // Deliberately not consumed: a mismatched caller must not be able to burn someone else's selection.
      return { ok: false, reason: binding.reason, audit: bindingAuditMetadata(binding.reason, stored, ctx) };
    }
    await this.redis.del(key);
    return { ok: true, pending };
  }

  /** First successful login flips INVITED -> ACTIVE and stamps has_been_active / last_login_at. */
  recordLogin(userId: string): Promise<void> {
    return this.rbac.recordLogin(userId);
  }

  async createSession(input: { userId: string; roleId: string; coreSid: string | null; aud: string | null; ipAddress: string | null; userAgent: string | null }): Promise<{ sessionToken: string; expiresAt: Date }> {
    const sessionToken = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
    await this.rbac.createSession({ ...input, sessionToken, expiresAt });
    return { sessionToken, expiresAt };
  }

  /**
   * The single path from a `miqaat_session` cookie to a session. Token shape, revocation, expiry and binding
   * (same IP + User-Agent as at login) are all decided here. Revocation and expiry are checked in code, so the
   * audit log can name which one failed instead of a blanket "not found".
   */
  async resolveSession(sessionToken: string, ctx: SessionBindingContext): Promise<SessionResolution> {
    if (typeof sessionToken !== 'string' || sessionToken.length < 16 || sessionToken.length > 512) {
      return { ok: false, reason: 'INVALID_TOKEN' };
    }
    const session = await this.rbac.findSession(sessionToken);
    if (!session) return { ok: false, reason: 'NOT_FOUND' };
    if (session.revokedAt) return { ok: false, reason: 'REVOKED' };
    if (new Date(session.expiresAt).getTime() <= Date.now()) return { ok: false, reason: 'EXPIRED' };

    const stored = { ipAddress: session.ipAddress, userAgent: session.userAgent };
    const binding = checkSessionBinding(stored, ctx);
    if (!binding.ok) return { ok: false, reason: binding.reason, audit: bindingAuditMetadata(binding.reason, stored, ctx) };

    return {
      ok: true,
      session: {
        sessionToken: session.sessionToken,
        expiresAt: session.expiresAt,
        user: toUser(session.user),
        role: toRole(session.role),
        roleStatus: session.role.status,
        tenantStatus: session.role.tenant?.status ?? null,
      },
    };
  }

  revokeSession(sessionToken: string): Promise<void> {
    return this.rbac.revokeSession(sessionToken);
  }

  /**
   * The role's grants collapsed into the shape a frontend menu needs: which modules it has any grant on, and which
   * actions within each. `dashboard` is not a real module row (never permission-gated) - added unconditionally.
   */
  async getModulePermissions(roleId: string, roleLevel: RoleLevel): Promise<{ modules: string[]; permissions: Record<string, Record<string, boolean>> }> {
    const permissions: Record<string, Record<string, boolean>> = { dashboard: { read: true } };
    for (const grant of await this.rbac.grantedModuleActions(roleId, roleLevel)) {
      (permissions[grant.module] ??= {})[grant.action] = true;
    }
    return { modules: Object.keys(permissions), permissions };
  }
}
