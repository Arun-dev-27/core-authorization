import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { ScopeLevel } from '@common/constants/rbac.constants';
import { DomainError } from '@common/errors/domain-error';
import { AuditService } from '@core/audit/audit.service';
import { queryMany, queryOne } from '@core/database/sql';
import { AuthzCacheService } from '@modules/authorization/services/authz-cache.service';
import { RbacService, RoleRow } from '@modules/rbac/services/rbac.service';
import { ActorContext } from '@shared/types/principal.types';

export interface CreateRoleInput {
  role_name: string;
  scope_level: ScopeLevel;
  permission_codes?: string[];
  tenant_id?: string;
}

export interface RolePermissionsInput {
  role_id: string;
  permission_codes: string[];
  action?: 'GRANT' | 'REVOKE';
}

const ROLE_SELECT = `
  SELECT r.role_id, r.tenant_id, r.role_name, r.scope_level, r.is_system_role, r.created_at, r.updated_at,
         COALESCE(array_agg(p.permission_code ORDER BY p.permission_code) FILTER (WHERE p.permission_code IS NOT NULL), '{}') AS permissions,
         (SELECT count(*)::int FROM user_roles ur WHERE ur.role_id = r.role_id) AS assignment_count
    FROM roles r
    LEFT JOIN role_permissions rp ON rp.role_id = r.role_id
    LEFT JOIN permissions p ON p.permission_id = rp.permission_id`;

@Injectable()
export class RolesService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly rbac: RbacService,
    private readonly audit: AuditService,
    private readonly cache: AuthzCacheService,
  ) {}

  /** Roles at the actor's level or below (CORE: all; BU: BU + utility roles; utility: utility roles). */
  list(actor: ActorContext, scopeLevel?: ScopeLevel) {
    return queryMany(
      this.db,
      `${ROLE_SELECT}
        WHERE ($1::uuid IS NULL OR r.tenant_id = $1) AND r.scope_level = ANY($2::varchar[]) AND ($3::varchar IS NULL OR r.scope_level = $3)
        GROUP BY r.role_id
        ORDER BY CASE r.scope_level WHEN 'CORE' THEN 0 WHEN 'BUSINESS_UNIT' THEN 1 ELSE 2 END, r.is_system_role DESC, r.role_name`,
      [actor.tenantId, this.rbac.manageableLevels(actor), scopeLevel ?? null],
    );
  }

  async get(actor: ActorContext, roleId: string) {
    const role = await this.rbac.roleById(roleId);
    this.rbac.assertTenant(actor, role.tenant_id, 'Role', roleId);
    if (!this.rbac.manageableLevels(actor).includes(role.scope_level)) throw DomainError.notFound('Role', roleId);
    return queryOne(this.db, `${ROLE_SELECT} WHERE r.role_id = $1 GROUP BY r.role_id`, [roleId]);
  }

  /** Custom role ("sub-role"): at or below the actor's level, never with permissions the actor lacks. */
  async create(actor: ActorContext, input: CreateRoleInput) {
    this.rbac.assertCanManageRoleLevel(actor, input.scope_level);
    const tenantId = await this.rbac.tenantForWrite(actor, input.tenant_id);
    const permissions = await this.rbac.permissionIds(input.permission_codes ?? []);
    this.rbac.assertNoEscalation(actor, permissions.map((p) => p.permission_code));

    const roleId = await this.db.transaction(async (tx) => {
      const role = await queryOne<{ role_id: string }>(
        tx,
        `INSERT INTO roles (tenant_id, role_name, scope_level, is_system_role) VALUES ($1, $2, $3, false) RETURNING role_id`,
        [tenantId, input.role_name, input.scope_level],
      );
      if (permissions.length > 0) {
        await tx.query(`INSERT INTO role_permissions (role_id, permission_id) SELECT $1, unnest($2::uuid[])`, [role!.role_id, permissions.map((p) => p.permission_id)]);
      }
      return role!.role_id;
    });
    await this.cache.invalidateAll();
    await this.audit.record({
      eventType: 'ROLE_CREATED',
      resourceType: 'role',
      resourceId: roleId,
      metadata: { role_name: input.role_name, scope_level: input.scope_level, permissions: permissions.map((p) => p.permission_code) },
    });
    return this.get(actor, roleId);
  }

  async rename(actor: ActorContext, roleId: string, roleName: string) {
    await this.loadManageable(actor, roleId);
    await this.db.query(`UPDATE roles SET role_name = $2 WHERE role_id = $1`, [roleId, roleName]);
    await this.audit.record({ eventType: 'ROLE_UPDATED', resourceType: 'role', resourceId: roleId, metadata: { role_name: roleName } });
    return this.get(actor, roleId);
  }

  async changePermissions(actor: ActorContext, input: RolePermissionsInput) {
    await this.loadManageable(actor, input.role_id);
    const permissions = await this.rbac.permissionIds(input.permission_codes);
    const ids = permissions.map((p) => p.permission_id);
    const grant = (input.action ?? 'GRANT') === 'GRANT';
    if (grant) {
      this.rbac.assertNoEscalation(actor, permissions.map((p) => p.permission_code));
      await this.db.query(`INSERT INTO role_permissions (role_id, permission_id) SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING`, [input.role_id, ids]);
    } else {
      await this.db.query(`DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = ANY($2::uuid[])`, [input.role_id, ids]);
    }
    await this.cache.invalidateAll();
    await this.audit.record({
      eventType: grant ? 'ROLE_PERMISSIONS_GRANTED' : 'ROLE_PERMISSIONS_REVOKED',
      resourceType: 'role',
      resourceId: input.role_id,
      metadata: { permissions: permissions.map((p) => p.permission_code) },
    });
    return this.get(actor, input.role_id);
  }

  /** System roles are only changed from a CORE workspace; others within the actor's manageable levels. */
  private async loadManageable(actor: ActorContext, roleId: string): Promise<RoleRow> {
    const role = await this.rbac.roleById(roleId);
    this.rbac.assertTenant(actor, role.tenant_id, 'Role', roleId);
    if (role.is_system_role && !actor.isCore) throw new DomainError('SYSTEM_ROLE_PROTECTED', 'Predefined system roles can only be changed by a Platform Administrator', 403);
    this.rbac.assertCanManageRoleLevel(actor, role.scope_level);
    return role;
  }
}
