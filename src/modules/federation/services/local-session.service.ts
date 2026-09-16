import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource, EntityManager } from 'typeorm';
import { ScopeLevel } from '@common/constants/rbac.constants';
import { DomainError } from '@common/errors/domain-error';
import { queryOne } from '@core/database/sql';

const S = 'miqaat_core';

/** A workspace's scope level decides the Core Admin role level it is recorded under. */
const ROLE_LEVEL: Record<ScopeLevel, string> = {
  CORE: 'CORE_ADMIN',
  BUSINESS_UNIT: 'BUSINESS_UNIT_ADMIN',
  UTILITY: 'UTILITY_ADMIN',
};

export interface RecordSessionInput {
  its_id: string;
  role_id: string;
  scope_type: ScopeLevel;
  scope_id?: string | null;
  core_sid: string;
  aud: string;
  session_token: string;
  expires_at: string;
  ip_address?: string | null;
  user_agent?: string | null;
}

export interface RecordedSession {
  session_id: string;
  user_id: string;
  role_id: string;
  core_sid: string;
  expires_at: string;
}

interface PublicUser {
  its_id: string;
  name: string;
  email: string | null;
  status: string;
}

interface PublicRole {
  role_id: string;
  role_name: string;
  scope_level: ScopeLevel;
}

/** miqaat_core.users.its_id only accepts exactly 8 digits (ck_users_its_id_8_digits). */
const ITS_8_DIGITS = /^[0-9]{8}$/;

/** role_code must match ck_roles_role_code_format: role-<segment>(-<segment>)*, lowercase alphanumeric. */
function slug(input: string): string {
  const value = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return value || 'unnamed';
}

/**
 * Records one signed-in session in the Core Admin Control Panel model (miqaat_core.user_sessions).
 *
 * Identity Federation owns authentication; this service only writes down the outcome, so the Control Panel
 * has the durable session history its data model calls for. No password, assertion or token is stored:
 * `session_token` is an opaque random token minted by Identity (never the assertion, an access token, a
 * refresh token or any JWT), and `core_sid` / `aud` identify the federation session and the client the
 * local session was established under.
 *
 * The Control Panel model (miqaat_core) and the live RBAC tables (public) are two separate user registries,
 * so a member and the role they selected are provisioned in miqaat_core on first sign-in:
 *  - users : matched on its_id when it is 8 digits, otherwise on a deterministic address, because
 *            miqaat_core.users.email is NOT NULL UNIQUE while public.users.email is neither.
 *  - roles : matched on a deterministic role_code derived from the role and its scope; the seeded
 *            'role-platform-administrator' is reused as-is for the CORE Platform Administrator.
 *  - tenants: the Business Unit / Utility the workspace belongs to (a non-CORE role requires a tenant).
 */
@Injectable()
export class LocalSessionService {
  private readonly logger = new Logger(LocalSessionService.name);

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  async record(input: RecordSessionInput): Promise<RecordedSession> {
    const expiresAt = new Date(input.expires_at);
    if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
      throw new DomainError('INVALID_SESSION_EXPIRY', 'expires_at must be a future timestamp');
    }
    const scopeId = input.scope_id ?? null;
    if (input.scope_type === 'CORE' ? scopeId !== null : scopeId === null) {
      throw new DomainError('INVALID_SCOPE', 'scope_id is required for BUSINESS_UNIT and UTILITY scopes, and empty for CORE');
    }

    return this.db.transaction(async (tx) => {
      const user = await queryOne<PublicUser>(tx, `SELECT its_id, name, email, status FROM users WHERE its_id = $1`, [input.its_id]);
      if (!user || user.status !== 'active') throw new DomainError('USER_NOT_FOUND', 'No active user with this ITS ID', 404);

      const role = await queryOne<PublicRole>(tx, `SELECT role_id, role_name, scope_level FROM roles WHERE role_id = $1`, [input.role_id]);
      if (!role) throw new DomainError('ROLE_NOT_FOUND', 'No role with this id', 404);

      // The session is only recorded for a workspace the user actually holds - the same rule the token was issued under.
      const held = await queryOne<{ ok: number }>(
        tx,
        `SELECT 1 AS ok FROM user_roles
          WHERE its_id = $1 AND role_id = $2 AND scope_type = $3 AND scope_id IS NOT DISTINCT FROM $4::uuid`,
        [input.its_id, input.role_id, input.scope_type, scopeId],
      );
      if (!held) throw new DomainError('ASSIGNMENT_NOT_FOUND', 'This workspace is not assigned to the user', 403);

      const scopeName = await this.scopeName(tx, input.scope_type, scopeId);
      const userId = await this.ensureUser(tx, user);
      const tenantId = await this.ensureTenant(tx, input.scope_type, scopeName);
      const roleId = await this.ensureRole(tx, role, input.scope_type, tenantId, scopeName);

      const session = await queryOne<{ id: string; expires_at: Date }>(
        tx,
        `INSERT INTO ${S}.user_sessions (user_id, role_id, core_sid, aud, session_token, ip_address, user_agent, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (session_token) DO NOTHING
         RETURNING id, expires_at`,
        [userId, roleId, input.core_sid, input.aud, input.session_token, input.ip_address ?? null, input.user_agent?.slice(0, 512) ?? null, expiresAt.toISOString()],
      );
      // The same token replayed is not a new session: return the row already recorded for it.
      const recorded =
        session ??
        (await queryOne<{ id: string; expires_at: Date }>(tx, `SELECT id, expires_at FROM ${S}.user_sessions WHERE session_token = $1`, [input.session_token]))!;

      this.logger.log({ msg: 'local session recorded', core_sid: input.core_sid, its_id: input.its_id, session_id: recorded.id });
      return {
        session_id: recorded.id,
        user_id: userId,
        role_id: roleId,
        core_sid: input.core_sid,
        expires_at: new Date(recorded.expires_at).toISOString(),
      };
    });
  }

  /** Back-channel logout: every live local session of one federation session ends with it. */
  async revokeByCoreSid(sid: string): Promise<number> {
    const result = (await this.db.query(
      `UPDATE ${S}.user_sessions SET revoked_at = now() WHERE core_sid = $1 AND revoked_at IS NULL RETURNING id`,
      [sid],
    )) as unknown[];
    const revoked = Array.isArray(result[0]) ? (result[0] as unknown[]).length : result.length;
    if (revoked > 0) this.logger.log({ msg: 'local sessions revoked', core_sid: sid, sessions: revoked });
    return revoked;
  }

  private async scopeName(tx: EntityManager, scopeType: ScopeLevel, scopeId: string | null): Promise<string | null> {
    if (scopeType === 'CORE') return null;
    const row =
      scopeType === 'BUSINESS_UNIT'
        ? await queryOne<{ name: string }>(tx, `SELECT name FROM business_units WHERE bu_id = $1`, [scopeId])
        : await queryOne<{ name: string }>(tx, `SELECT name FROM utilities WHERE utility_id = $1`, [scopeId]);
    if (!row) throw new DomainError('SCOPE_NOT_FOUND', 'The workspace scope does not exist', 404);
    return row.name;
  }

  /**
   * miqaat_core.users demands a unique, non-null email, which the live RBAC table does not guarantee
   * (many accounts share one address or have none). The real address is kept when it is still free;
   * otherwise the member is recorded under a deterministic, non-routable address derived from the ITS ID.
   */
  private async ensureUser(tx: EntityManager, user: PublicUser): Promise<string> {
    const isIts = ITS_8_DIGITS.test(user.its_id);
    const fallbackEmail = `its-${user.its_id.toLowerCase()}@members.miqaat.local`;

    const existing = isIts
      ? await queryOne<{ id: string }>(tx, `SELECT id FROM ${S}.users WHERE its_id = $1`, [user.its_id])
      : await queryOne<{ id: string }>(tx, `SELECT id FROM ${S}.users WHERE lower(email) = lower($1)`, [fallbackEmail]);
    if (existing) {
      await tx.query(`UPDATE ${S}.users SET status = 'ACTIVE', has_been_active = true, last_login_at = now() WHERE id = $1`, [existing.id]);
      return existing.id;
    }

    const emailFree =
      user.email !== null && (await queryOne<{ ok: number }>(tx, `SELECT 1 AS ok FROM ${S}.users WHERE lower(email) = lower($1)`, [user.email])) === null;
    const email = emailFree ? user.email! : fallbackEmail;

    const inserted = await queryOne<{ id: string }>(
      tx,
      `INSERT INTO ${S}.users (its_id, name, email, status, has_been_active, last_login_at)
       VALUES ($1, $2, $3, 'ACTIVE', true, now())
       ON CONFLICT DO NOTHING
       RETURNING id`,
      [isIts ? user.its_id : null, user.name, email],
    );
    if (inserted) return inserted.id;

    const raced = isIts
      ? await queryOne<{ id: string }>(tx, `SELECT id FROM ${S}.users WHERE its_id = $1`, [user.its_id])
      : await queryOne<{ id: string }>(tx, `SELECT id FROM ${S}.users WHERE lower(email) = lower($1)`, [email]);
    if (!raced) throw new DomainError('USER_PROVISIONING_FAILED', 'The member could not be recorded in the Control Panel model', 500);
    return raced.id;
  }

  /** A Business Unit or Utility workspace needs its tenant; CORE roles carry no tenant (ck_roles_tenant_scope). */
  private async ensureTenant(tx: EntityManager, scopeType: ScopeLevel, scopeName: string | null): Promise<string | null> {
    if (scopeType === 'CORE' || scopeName === null) return null;
    const tenantType = scopeType === 'BUSINESS_UNIT' ? 'BUSINESS_UNIT' : 'UTILITY';
    const select = `SELECT id FROM ${S}.tenants WHERE tenant_type = $1 AND lower(trim(name)) = lower(trim($2))`;

    const existing = await queryOne<{ id: string }>(tx, select, [tenantType, scopeName]);
    if (existing) return existing.id;

    const inserted = await queryOne<{ id: string }>(
      tx,
      `INSERT INTO ${S}.tenants (tenant_type, name) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING id`,
      [tenantType, scopeName],
    );
    if (inserted) return inserted.id;

    const raced = await queryOne<{ id: string }>(tx, select, [tenantType, scopeName]);
    if (!raced) throw new DomainError('TENANT_PROVISIONING_FAILED', 'The workspace tenant could not be recorded', 500);
    return raced.id;
  }

  private async ensureRole(tx: EntityManager, role: PublicRole, scopeType: ScopeLevel, tenantId: string | null, scopeName: string | null): Promise<string> {
    const roleCode = scopeName === null ? `role-${slug(role.role_name)}` : `role-${slug(role.role_name)}-${slug(scopeName)}`;

    const existing = await queryOne<{ id: string }>(tx, `SELECT id FROM ${S}.roles WHERE role_code = $1`, [roleCode]);
    if (existing) return existing.id;

    const inserted = await queryOne<{ id: string }>(
      tx,
      `INSERT INTO ${S}.roles (role_level, tenant_id, role_code, name) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING id`,
      [ROLE_LEVEL[scopeType], tenantId, roleCode, role.role_name],
    );
    if (inserted) return inserted.id;

    const raced = await queryOne<{ id: string }>(tx, `SELECT id FROM ${S}.roles WHERE role_code = $1`, [roleCode]);
    if (!raced) throw new DomainError('ROLE_PROVISIONING_FAILED', 'The workspace role could not be recorded', 500);
    return raced.id;
  }
}
