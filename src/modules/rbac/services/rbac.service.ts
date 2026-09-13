import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { actionRank, manageableLevels, moduleRank, ScopeLevel } from '@common/constants/rbac.constants';
import { UUID } from '@common/constants/validation.constants';
import { DomainError } from '@common/errors/domain-error';
import { Queryable, queryMany, queryOne } from '@core/database/sql';
import { ActorContext, Principal } from '@shared/types/principal.types';

/** One role held by a user in one scope (a "workspace"). */
export interface Assignment {
  role_id: string;
  role_name: string;
  scope_type: ScopeLevel;
  scope_id: string | null;
  scope_name: string | null;
  scope_bu_id: string | null;
  tenant_id: string;
  is_system_role: boolean;
  assigned_at: Date;
}

export interface ActiveScope {
  role_id: string;
  role_name: string;
  scope_type: ScopeLevel;
  scope_id: string | null;
  scope_name: string | null;
}

export interface RolePermissionRow {
  permission_code: string;
  action: string;
  module_code: string;
  application_id: string | null;
}

export interface RoleRow {
  role_id: string;
  tenant_id: string;
  role_name: string;
  scope_level: ScopeLevel;
  is_system_role: boolean;
}

interface ScopeEntity {
  tenant_id: string;
  bu_id: string;
  utility_id: string | null;
  status: string;
}

const ASSIGNMENT_SELECT = `
  SELECT ur.role_id, r.role_name, ur.scope_type, ur.scope_id,
         CASE ur.scope_type WHEN 'CORE' THEN t.name WHEN 'BUSINESS_UNIT' THEN bu.name ELSE ut.name END AS scope_name,
         CASE ur.scope_type WHEN 'BUSINESS_UNIT' THEN bu.bu_id WHEN 'UTILITY' THEN ut.bu_id ELSE NULL END AS scope_bu_id,
         r.tenant_id, r.is_system_role, ur.assigned_at
    FROM user_roles ur
    JOIN roles r ON r.role_id = ur.role_id
    JOIN tenants t ON t.tenant_id = r.tenant_id
    LEFT JOIN business_units bu ON ur.scope_type = 'BUSINESS_UNIT' AND bu.bu_id = ur.scope_id
    LEFT JOIN utilities ut ON ur.scope_type = 'UTILITY' AND ut.utility_id = ur.scope_id
    LEFT JOIN business_units ubu ON ubu.bu_id = ut.bu_id`;

/** Only usable assignments: active user and tenant, active BU / utility (and the utility's BU). */
const USABLE = `
    JOIN users u ON u.its_id = ur.its_id AND u.status = 'active' AND u.tenant_id = r.tenant_id
   WHERE t.status = 'active'
     AND (ur.scope_type = 'CORE'
          OR (ur.scope_type = 'BUSINESS_UNIT' AND bu.status = 'active')
          OR (ur.scope_type = 'UTILITY' AND ut.status = 'active' AND ubu.status = 'active'))`;

const ORDER = `ORDER BY CASE ur.scope_type WHEN 'CORE' THEN 0 WHEN 'BUSINESS_UNIT' THEN 1 ELSE 2 END, scope_name, r.role_name`;

/**
 * Core RBAC rules shared by every feature:
 *  - resolves a user's workspaces (role × scope) and the active one from the token
 *  - CORE sees the whole tenant; BUSINESS_UNIT its BU and the utilities under it; UTILITY only its utility
 *  - roles can only be created / assigned at the actor's level or below ("Can create sub-roles?")
 *  - a non-CORE actor can never grant permissions it does not hold itself (no privilege escalation)
 */
@Injectable()
export class RbacService {
  private defaultTenant?: { id: string; at: number };

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly config: AppConfig,
  ) {}

  // ------------------------------------------------------------------ assignments / workspaces

  listAssignments(itsId: string, db: Queryable = this.db): Promise<Assignment[]> {
    return queryMany<Assignment>(db, `${ASSIGNMENT_SELECT} ${USABLE} AND ur.its_id = $1 ${ORDER}`, [itsId]);
  }

  /** Every assignment of a user regardless of status (administration views). */
  allAssignments(itsId: string, db: Queryable = this.db): Promise<Assignment[]> {
    return queryMany<Assignment>(db, `${ASSIGNMENT_SELECT} WHERE ur.its_id = $1 ${ORDER}`, [itsId]);
  }

  async findAssignment(itsId: string, roleId: string, scopeType: ScopeLevel, scopeId: string | null): Promise<Assignment | null> {
    if (!UUID.test(roleId) || (scopeId !== null && !UUID.test(scopeId))) return null;
    return queryOne<Assignment>(
      this.db,
      `${ASSIGNMENT_SELECT} ${USABLE} AND ur.its_id = $1 AND ur.role_id = $2 AND ur.scope_type = $3 AND ur.scope_id IS NOT DISTINCT FROM $4::uuid`,
      [itsId, roleId, scopeType, scopeId],
    );
  }

  toActiveScope(a: Assignment): ActiveScope {
    return { role_id: a.role_id, role_name: a.role_name, scope_type: a.scope_type, scope_id: a.scope_id, scope_name: a.scope_name };
  }

  // ------------------------------------------------------------------ permissions

  rolePermissions(roleId: string, db: Queryable = this.db): Promise<RolePermissionRow[]> {
    return queryMany<RolePermissionRow>(
      db,
      `SELECT p.permission_code, p.action, m.module_code, m.application_id
         FROM role_permissions rp
         JOIN permissions p ON p.permission_id = rp.permission_id
         JOIN modules m ON m.module_id = p.module_id
        WHERE rp.role_id = $1`,
      [roleId],
    );
  }

  /** GET /me/permissions shape: { MODULE_CODE: [actions] } for the Core Portal modules of one role. Missing key = hidden. */
  async permissionMap(roleId: string): Promise<Record<string, string[]>> {
    const rows = (await this.rolePermissions(roleId)).filter((r) => r.application_id === null);
    rows.sort((a, b) => moduleRank(a.module_code) - moduleRank(b.module_code) || a.module_code.localeCompare(b.module_code) || actionRank(a.action) - actionRank(b.action));
    const map: Record<string, string[]> = {};
    for (const row of rows) (map[row.module_code] ??= []).push(row.action);
    return map;
  }

  hasPermission(actor: ActorContext, code: string): boolean {
    return actor.permissions === 'ALL' || actor.permissions.has(code);
  }

  // ------------------------------------------------------------------ actor

  async actorFor(principal: Principal): Promise<ActorContext> {
    if (principal.kind === 'service') {
      return {
        kind: 'service', label: `svc:${principal.id}`, itsId: null, tenantId: null, isCore: true, scopeType: 'CORE',
        scopeId: null, scopeBuId: null, scopeName: null, roleId: null, roleName: null, permissions: 'ALL',
      };
    }
    const scope = principal.activeScope;
    if (!scope) throw new DomainError('SCOPE_SELECTION_REQUIRED', 'Select a workspace (POST /select-scope) before calling this endpoint', 403);
    const assignment = await this.findAssignment(principal.itsId, scope.role_id, scope.scope_type, scope.scope_id);
    if (!assignment) throw new DomainError('ASSIGNMENT_NOT_ACTIVE', 'The selected workspace is no longer assigned to you', 403);
    const permissions = new Set((await this.rolePermissions(assignment.role_id)).map((p) => p.permission_code));
    return {
      kind: 'user',
      label: `user:${principal.itsId}`,
      itsId: principal.itsId,
      tenantId: assignment.tenant_id,
      isCore: assignment.scope_type === 'CORE',
      scopeType: assignment.scope_type,
      scopeId: assignment.scope_id,
      scopeBuId: assignment.scope_bu_id,
      scopeName: assignment.scope_name,
      roleId: assignment.role_id,
      roleName: assignment.role_name,
      permissions,
    };
  }

  // ------------------------------------------------------------------ tenants

  async defaultTenantId(): Promise<string> {
    if (this.defaultTenant && Date.now() - this.defaultTenant.at < 60_000) return this.defaultTenant.id;
    const row = await queryOne<{ tenant_id: string }>(this.db, `SELECT tenant_id FROM tenants WHERE name = $1`, [this.config.env.DEFAULT_TENANT_NAME]);
    if (!row) throw new DomainError('DEFAULT_TENANT_NOT_FOUND', `Tenant '${this.config.env.DEFAULT_TENANT_NAME}' does not exist; run the catalog seed`, 500);
    this.defaultTenant = { id: row.tenant_id, at: Date.now() };
    return row.tenant_id;
  }

  /** Tenant for a new record: the actor's own tenant; an ADMIN service may name one (or gets the default). */
  async tenantForWrite(actor: ActorContext, requested?: string | null): Promise<string> {
    if (actor.tenantId) {
      if (requested && requested !== actor.tenantId) throw new DomainError('TENANT_NOT_PERMITTED', 'You cannot create records in another tenant', 403);
      return actor.tenantId;
    }
    if (!requested) return this.defaultTenantId();
    const row = await queryOne(this.db, `SELECT 1 FROM tenants WHERE tenant_id = $1`, [requested]);
    if (!row) throw DomainError.notFound('Tenant', requested);
    return requested;
  }

  /** Records of other tenants are reported as not found. */
  assertTenant(actor: ActorContext, tenantId: string, what: string, id: string): void {
    if (actor.tenantId && actor.tenantId !== tenantId) throw DomainError.notFound(what, id);
  }

  // ------------------------------------------------------------------ scopes

  async scopeEntity(scopeType: 'BUSINESS_UNIT' | 'UTILITY', scopeId: string): Promise<ScopeEntity | null> {
    if (!UUID.test(scopeId)) return null;
    return scopeType === 'BUSINESS_UNIT'
      ? queryOne<ScopeEntity>(this.db, `SELECT tenant_id, bu_id, NULL::uuid AS utility_id, status FROM business_units WHERE bu_id = $1`, [scopeId])
      : queryOne<ScopeEntity>(
          this.db,
          `SELECT bu.tenant_id, u.bu_id, u.utility_id, u.status FROM utilities u JOIN business_units bu ON bu.bu_id = u.bu_id WHERE u.utility_id = $1`,
          [scopeId],
        );
  }

  /** The actor may act on (create in, assign into) this scope. Returns the scope entity for BU / utility scopes. */
  async assertCanTargetScope(actor: ActorContext, scopeType: ScopeLevel, scopeId: string | null | undefined): Promise<ScopeEntity | null> {
    if (scopeType === 'CORE') {
      if (scopeId) throw new DomainError('INVALID_SCOPE', 'scope_id must be empty for CORE scope');
      if (!actor.isCore) throw new DomainError('SCOPE_NOT_PERMITTED', 'Only a CORE workspace can act on the CORE scope', 403);
      return null;
    }
    if (!scopeId) throw new DomainError('INVALID_SCOPE', `scope_id is required for ${scopeType} scope`);
    const entity = await this.scopeEntity(scopeType, scopeId);
    const label = scopeType === 'BUSINESS_UNIT' ? 'Business unit' : 'Utility';
    if (!entity) throw DomainError.notFound(label, scopeId);
    this.assertTenant(actor, entity.tenant_id, label, scopeId);
    if (actor.isCore) return entity;
    const allowed =
      actor.scopeType === 'BUSINESS_UNIT' ? entity.bu_id === actor.scopeId : scopeType === 'UTILITY' && entity.utility_id === actor.scopeId;
    if (!allowed) throw new DomainError('SCOPE_NOT_PERMITTED', `This ${label.toLowerCase()} is outside your workspace`, 403);
    return entity;
  }

  assignmentWithinScope(actor: ActorContext, a: Pick<Assignment, 'scope_type' | 'scope_id' | 'scope_bu_id'>): boolean {
    if (actor.isCore) return true;
    if (actor.scopeType === 'BUSINESS_UNIT') {
      return (a.scope_type === 'BUSINESS_UNIT' && a.scope_id === actor.scopeId) || (a.scope_type === 'UTILITY' && a.scope_bu_id === actor.scopeId);
    }
    return a.scope_type === 'UTILITY' && a.scope_id === actor.scopeId;
  }

  manageableLevels(actor: ActorContext): ScopeLevel[] {
    return manageableLevels(actor.scopeType);
  }

  assertCanManageRoleLevel(actor: ActorContext, level: ScopeLevel): void {
    if (!this.manageableLevels(actor).includes(level)) {
      throw new DomainError('ROLE_LEVEL_NOT_PERMITTED', `A ${actor.scopeType} workspace cannot manage ${level} roles`, 403);
    }
  }

  /** Non-CORE actors may only hand out permissions they hold in their active workspace. */
  assertNoEscalation(actor: ActorContext, codes: string[]): void {
    if (actor.isCore || actor.permissions === 'ALL') return;
    const missing = [...new Set(codes)].filter((code) => !(actor.permissions as ReadonlySet<string>).has(code)).sort();
    if (missing.length > 0) {
      throw new DomainError('PERMISSION_ESCALATION', 'You cannot grant permissions you do not hold', 403, { missing });
    }
  }

  // ------------------------------------------------------------------ lookups

  async roleById(roleId: string, db: Queryable = this.db): Promise<RoleRow> {
    const row = UUID.test(roleId)
      ? await queryOne<RoleRow>(db, `SELECT role_id, tenant_id, role_name, scope_level, is_system_role FROM roles WHERE role_id = $1`, [roleId])
      : null;
    if (!row) throw DomainError.notFound('Role', roleId);
    return row;
  }

  async applicationByCode(code: string): Promise<{ id: string; code: string; name: string; tenant_id: string }> {
    const row = await queryOne<{ id: string; code: string; name: string; tenant_id: string }>(
      this.db,
      `SELECT application_id AS id, code, name, tenant_id FROM applications WHERE code = $1`,
      [code],
    );
    if (!row) throw DomainError.notFound('Application', code);
    return row;
  }

  async environmentByCode(code: string): Promise<{ id: string; code: string }> {
    const row = await queryOne<{ id: string; code: string }>(this.db, `SELECT id, code FROM environments WHERE code = $1`, [code]);
    if (!row) throw DomainError.notFound('Environment', code);
    return row;
  }

  /** Resolves permission codes to ids; unknown codes are reported together. */
  async permissionIds(codes: string[], db: Queryable = this.db): Promise<{ permission_id: string; permission_code: string }[]> {
    const unique = [...new Set(codes)];
    if (unique.length === 0) return [];
    const rows = await queryMany<{ permission_id: string; permission_code: string }>(
      db,
      `SELECT permission_id, permission_code FROM permissions WHERE permission_code = ANY($1)`,
      [unique],
    );
    const found = new Set(rows.map((r) => r.permission_code));
    const missing = unique.filter((c) => !found.has(c));
    if (missing.length > 0) throw new DomainError('PERMISSION_NOT_FOUND', 'One or more permissions do not exist', 404, { missing });
    return rows;
  }
}
