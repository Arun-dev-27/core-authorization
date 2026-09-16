import { randomBytes } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import type Redis from 'ioredis';
import { DataSource } from 'typeorm';
import { REDIS } from '@core/cache/redis.module';
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
  roleLevel: 'CORE_ADMIN' | 'BUSINESS_UNIT_ADMIN' | 'UTILITY_ADMIN';
  tenantId: string | null;
  tenantName: string | null;
}

export interface LocalSession {
  sessionToken: string;
  expiresAt: Date;
  user: MiqaatCoreUser;
  role: MiqaatCoreRole;
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

const ROLE_SELECT = `
  SELECT r.id AS role_id, r.role_code, r.name AS role_name, r.role_level, r.tenant_id, t.name AS tenant_name
    FROM miqaat_core.user_roles ur
    JOIN miqaat_core.roles r ON r.id = ur.role_id AND r.status = 'ACTIVE'
    LEFT JOIN miqaat_core.tenants t ON t.id = r.tenant_id
   WHERE ur.user_id = $1 AND (t.id IS NULL OR t.status = 'ACTIVE')`;

function toRole(r: { role_id: string; role_code: string; role_name: string; role_level: MiqaatCoreRole['roleLevel']; tenant_id: string | null; tenant_name: string | null }): MiqaatCoreRole {
  return { roleId: r.role_id, roleCode: r.role_code, roleName: r.role_name, roleLevel: r.role_level, tenantId: r.tenant_id, tenantName: r.tenant_name };
}

/**
 * The miqaat_core (Core Admin Control Panel) schema's own local session - deliberately separate from
 * the `public` schema tables the rest of this service's Federation Authorization APIs use (business_units,
 * applications, the older users/roles). See docs on MiqaatCoreSchema1789600000000 for why the two coexist.
 * Raw SQL, schema-qualified throughout: no TypeORM entities are defined for miqaat_core yet.
 */
@Injectable()
export class LocalSessionService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    @Inject(REDIS) private readonly redis: Redis,
  ) {}

  async findUserByItsId(itsId: string): Promise<MiqaatCoreUser | null> {
    const rows = await this.db.query(`SELECT id, its_id, name, email, status FROM miqaat_core.users WHERE its_id = $1`, [itsId]);
    if (!rows.length) return null;
    const r = rows[0];
    return { id: r.id, itsId: r.its_id, name: r.name, email: r.email, status: r.status };
  }

  /**
   * Every role this user currently holds (tenant scoped or the one platform-wide CORE_ADMIN role), ordered
   * so a stable "first" choice exists if the caller ever needs one. A user legitimately holding more than
   * one (the schema allows one role per tenant, `uq_user_roles_one_role_per_tenant`) must pick which to act
   * as - see `SessionController` "Where do you want to log in?" step.
   */
  async listRolesForUser(userId: string): Promise<MiqaatCoreRole[]> {
    const rows = await this.db.query(`${ROLE_SELECT} ORDER BY (t.name IS NULL) DESC, t.name, r.name`, [userId]);
    return rows.map(toRole);
  }

  /** Re-validates a chosen role_id still belongs to this user at selection time (schema/roles can change between the two calls). */
  async findRoleForUser(userId: string, roleId: string): Promise<MiqaatCoreRole | null> {
    const rows = await this.db.query(`${ROLE_SELECT} AND r.id = $2`, [userId, roleId]);
    return rows.length ? toRole(rows[0]) : null;
  }

  /**
   * Holds "assertion verified, awaiting role selection" between the two calls a multi-role login needs.
   * Short-lived and one-time (deleted on `consumePendingSelection`) — the `core_assertion` itself can't be
   * resubmitted for step two, its `jti` is already burned by `AssertionVerifierService`. Redis, not a table:
   * this state is never queried, audited, or needed past a few minutes, unlike `user_sessions`.
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

  /** First successful login flips INVITED -> ACTIVE and stamps has_been_active/last_login_at (mirrors the schema's own note). */
  async recordLogin(userId: string): Promise<void> {
    await this.db.query(
      `UPDATE miqaat_core.users
          SET last_login_at = now(), has_been_active = true, status = CASE WHEN status = 'INVITED' THEN 'ACTIVE' ELSE status END
        WHERE id = $1`,
      [userId],
    );
  }

  async createSession(input: { userId: string; roleId: string; coreSid: string | null; aud: string | null; ipAddress: string | null; userAgent: string | null }): Promise<{ sessionToken: string; expiresAt: Date }> {
    const sessionToken = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
    await this.db.query(
      `INSERT INTO miqaat_core.user_sessions (user_id, role_id, core_sid, aud, session_token, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [input.userId, input.roleId, input.coreSid, input.aud, sessionToken, input.ipAddress, input.userAgent, expiresAt],
    );
    return { sessionToken, expiresAt };
  }

  /**
   * The single path from a `miqaat_session` cookie to a session. Token shape, revocation, expiry and
   * binding (same IP + User-Agent as at login) are all decided here, so no caller can reach a session
   * with any one of them unchecked. Revocation and expiry are evaluated in code rather than filtered
   * out in SQL, so the audit log can name which one failed instead of a blanket "not found".
   */
  async resolveSession(sessionToken: string, ctx: SessionBindingContext): Promise<SessionResolution> {
    if (typeof sessionToken !== 'string' || sessionToken.length < 16 || sessionToken.length > 512) {
      return { ok: false, reason: 'INVALID_TOKEN' };
    }
    const rows = await this.db.query(
      `SELECT s.session_token, s.expires_at, s.revoked_at, s.ip_address, s.user_agent,
              u.id AS user_id, u.its_id, u.name AS user_name, u.email, u.status AS user_status,
              r.id AS role_id, r.role_code, r.name AS role_name, r.role_level, r.tenant_id, t.name AS tenant_name
         FROM miqaat_core.user_sessions s
         JOIN miqaat_core.users u ON u.id = s.user_id
         JOIN miqaat_core.roles r ON r.id = s.role_id
         LEFT JOIN miqaat_core.tenants t ON t.id = r.tenant_id
        WHERE s.session_token = $1`,
      [sessionToken],
    );
    if (!rows.length) return { ok: false, reason: 'NOT_FOUND' };
    const r = rows[0];
    if (r.revoked_at) return { ok: false, reason: 'REVOKED' };
    if (new Date(r.expires_at).getTime() <= Date.now()) return { ok: false, reason: 'EXPIRED' };

    const stored = { ipAddress: r.ip_address as string | null, userAgent: r.user_agent as string | null };
    const binding = checkSessionBinding(stored, ctx);
    if (!binding.ok) return { ok: false, reason: binding.reason, audit: bindingAuditMetadata(binding.reason, stored, ctx) };

    return {
      ok: true,
      session: {
        sessionToken: r.session_token,
        expiresAt: r.expires_at,
        user: { id: r.user_id, itsId: r.its_id, name: r.user_name, email: r.email, status: r.user_status },
        role: { roleId: r.role_id, roleCode: r.role_code, roleName: r.role_name, roleLevel: r.role_level, tenantId: r.tenant_id, tenantName: r.tenant_name },
      },
    };
  }

  async revokeSession(sessionToken: string): Promise<void> {
    await this.db.query(`UPDATE miqaat_core.user_sessions SET revoked_at = now() WHERE session_token = $1 AND revoked_at IS NULL`, [sessionToken]);
  }

  /**
   * The Permission Matrix (MiqaatCoreSchema's role_permissions), collapsed into the shape a frontend menu
   * needs: which modules this role actually has any grant on, and which actions within each. `dashboard`
   * is not a real module row (never permission-gated, per that migration's own note) - added unconditionally.
   */
  async getModulePermissions(roleId: string, roleLevel: MiqaatCoreRole['roleLevel']): Promise<{ modules: string[]; permissions: Record<string, Record<string, boolean>> }> {
    const rows = await this.db.query(
      `SELECT lower(m.code) AS module_code, lower(a.code) AS action_code
         FROM miqaat_core.role_permissions rp
         JOIN miqaat_core.module_actions ma ON ma.id = rp.module_action_id
         JOIN miqaat_core.modules m ON m.id = ma.module_id
         JOIN miqaat_core.permission_actions a ON a.id = ma.action_id
        WHERE rp.role_id = $1
          AND (CASE WHEN $2 = 'CORE_ADMIN' THEN m.applies_to_core AND ma.applies_to_core ELSE m.applies_to_tenant AND ma.applies_to_tenant END)`,
      [roleId, roleLevel],
    );
    const permissions: Record<string, Record<string, boolean>> = { dashboard: { read: true } };
    for (const r of rows as { module_code: string; action_code: string }[]) {
      (permissions[r.module_code] ??= {})[r.action_code] = true;
    }
    return { modules: Object.keys(permissions), permissions };
  }
}
