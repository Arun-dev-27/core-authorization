import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { ScopeLevel, UserStatus } from '@common/constants/rbac.constants';
import { DomainError } from '@common/errors/domain-error';
import { AuditService } from '@core/audit/audit.service';
import { queryOne, returningRows } from '@core/database/sql';
import { AuthzCacheService } from '@modules/authorization/services/authz-cache.service';
import { Assignment, RbacService } from '@modules/rbac/services/rbac.service';
import { ActorContext } from '@shared/types/principal.types';

export interface CreateUserInput {
  its_id: string;
  name: string;
  email?: string;
  status?: UserStatus;
}

export interface UpdateUserInput {
  name?: string;
  email?: string;
  status?: UserStatus;
}

export interface SyncUserInput {
  its_id: string;
  name?: string;
  email?: string;
  status?: UserStatus;
}

export interface UserRoleInput {
  its_id: string;
  role_id: string;
  scope_type: ScopeLevel;
  scope_id?: string | null;
}

interface UserRow {
  its_id: string;
  tenant_id: string;
  name: string;
  email: string | null;
  status: UserStatus;
}

const COLUMNS = 'its_id, tenant_id, name, email, status, created_at, updated_at';
const NIL = `'00000000-0000-0000-0000-000000000000'::uuid`;

function publicAssignment(a: Assignment) {
  return {
    role_id: a.role_id,
    role_name: a.role_name,
    is_system_role: a.is_system_role,
    scope_type: a.scope_type,
    scope_id: a.scope_id,
    scope_name: a.scope_name,
    assigned_at: a.assigned_at,
  };
}

@Injectable()
export class UsersService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly rbac: RbacService,
    private readonly audit: AuditService,
    private readonly cache: AuthzCacheService,
  ) {}

  /** Profile + assignments. Non-CORE workspaces see only assignments inside their scope (and users without any). */
  async get(actor: ActorContext, itsId: string) {
    const user = await this.loadUser(actor, itsId);
    const assignments = await this.rbac.allAssignments(itsId);
    const visible = assignments.filter((a) => this.rbac.assignmentWithinScope(actor, a));
    if (!actor.isCore && assignments.length > 0 && visible.length === 0) throw DomainError.notFound('User', itsId);
    return { ...user, assignments: visible.map(publicAssignment) };
  }

  async create(actor: ActorContext, input: CreateUserInput) {
    const tenantId = await this.rbac.tenantForWrite(actor);
    const row = await queryOne(
      this.db,
      `INSERT INTO users (its_id, tenant_id, name, email, status) VALUES ($1, $2, $3, $4, COALESCE($5, 'active')) RETURNING ${COLUMNS}`,
      [input.its_id, tenantId, input.name, input.email?.toLowerCase() ?? null, input.status ?? null],
    );
    await this.audit.record({ eventType: 'USER_CREATED', itsId: input.its_id, resourceType: 'user', resourceId: input.its_id });
    return row;
  }

  /** Non-CORE workspaces may only edit users whose every assignment lies inside their scope. */
  async update(actor: ActorContext, itsId: string, input: UpdateUserInput) {
    await this.loadUser(actor, itsId);
    if (!actor.isCore) {
      const outside = (await this.rbac.allAssignments(itsId)).filter((a) => !this.rbac.assignmentWithinScope(actor, a));
      if (outside.length > 0) throw new DomainError('USER_OUTSIDE_SCOPE', 'This user holds roles outside your workspace', 403);
    }
    const [row] = returningRows(
      await this.db.query(
        `UPDATE users SET name = COALESCE($2, name), email = COALESCE($3, email), status = COALESCE($4, status) WHERE its_id = $1 RETURNING ${COLUMNS}`,
        [itsId, input.name ?? null, input.email?.toLowerCase() ?? null, input.status ?? null],
      ),
    );
    await this.cache.invalidateAll();
    await this.audit.record({ eventType: 'USER_UPDATED', itsId, resourceType: 'user', resourceId: itsId, metadata: { fields: Object.keys(input) } });
    return row;
  }

  /** Profile sync from Identity Federation (never credentials). New users join the default tenant. */
  async sync(input: SyncUserInput) {
    const tenantId = await this.rbac.defaultTenantId();
    const row = await queryOne<{ inserted: boolean }>(
      this.db,
      `INSERT INTO users (its_id, tenant_id, name, email, status) VALUES ($1::varchar, $2, COALESCE($3::varchar, $1::varchar), $4::varchar, COALESCE($5::varchar, 'active'))
       ON CONFLICT (its_id) DO UPDATE SET
         name   = COALESCE($3, users.name),
         email  = COALESCE($4, users.email),
         status = COALESCE($5, users.status)
       RETURNING ${COLUMNS}, (xmax = 0) AS inserted`,
      [input.its_id, tenantId, input.name ?? null, input.email?.toLowerCase() ?? null, input.status ?? null],
    );
    await this.cache.invalidateAll();
    await this.audit.record({
      eventType: row!.inserted ? 'USER_CREATED' : 'USER_SYNCED',
      itsId: input.its_id,
      resourceType: 'user',
      resourceId: input.its_id,
      metadata: { fields: Object.keys(input).filter((k) => k !== 'its_id') },
    });
    return row;
  }

  async listRoles(actor: ActorContext, itsId: string) {
    return (await this.get(actor, itsId)).assignments;
  }

  /** Assign a role in a scope: role level = scope type, scope inside the actor's workspace, no escalation. */
  async assign(actor: ActorContext, input: UserRoleInput) {
    await this.checkAssignment(actor, input);
    const scopeId = input.scope_id ?? null;
    const rows = (await this.db.query(
      `INSERT INTO user_roles (its_id, role_id, scope_type, scope_id) VALUES ($1, $2, $3, $4)
       ON CONFLICT (its_id, role_id, (COALESCE(scope_id, ${NIL}))) DO NOTHING
       RETURNING its_id`,
      [input.its_id, input.role_id, input.scope_type, scopeId],
    )) as unknown[];
    if (rows.length === 0) throw DomainError.conflict('ASSIGNMENT_EXISTS', 'The user already holds this role in this scope');
    await this.cache.invalidateAll();
    await this.audit.record({ eventType: 'USER_ROLE_ASSIGNED', itsId: input.its_id, resourceType: 'role', resourceId: input.role_id, metadata: { scope_type: input.scope_type, scope_id: scopeId } });
    return this.findAssignmentView(input.its_id, input.role_id, scopeId);
  }

  async revoke(actor: ActorContext, input: UserRoleInput) {
    await this.checkAssignment(actor, input);
    const scopeId = input.scope_id ?? null;
    const [deleted] = returningRows(
      await this.db.query(`DELETE FROM user_roles WHERE its_id = $1 AND role_id = $2 AND scope_id IS NOT DISTINCT FROM $3::uuid RETURNING its_id`, [
        input.its_id,
        input.role_id,
        scopeId,
      ]),
    );
    if (!deleted) throw new DomainError('ASSIGNMENT_NOT_FOUND', 'The user does not hold this role in this scope', 404);
    await this.cache.invalidateAll();
    await this.audit.record({ eventType: 'USER_ROLE_REVOKED', itsId: input.its_id, resourceType: 'role', resourceId: input.role_id, metadata: { scope_type: input.scope_type, scope_id: scopeId } });
    return { revoked: true, its_id: input.its_id, role_id: input.role_id, scope_type: input.scope_type, scope_id: scopeId };
  }

  private async checkAssignment(actor: ActorContext, input: UserRoleInput): Promise<void> {
    const user = await this.loadUser(actor, input.its_id);
    const role = await this.rbac.roleById(input.role_id);
    this.rbac.assertTenant(actor, role.tenant_id, 'Role', input.role_id);
    if (role.tenant_id !== user.tenant_id) throw new DomainError('TENANT_MISMATCH', 'User and role belong to different tenants');
    if (role.scope_level !== input.scope_type) {
      throw new DomainError('SCOPE_TYPE_MISMATCH', `Role '${role.role_name}' is a ${role.scope_level} role and cannot be assigned at ${input.scope_type} scope`);
    }
    await this.rbac.assertCanTargetScope(actor, input.scope_type, input.scope_id ?? null);
    this.rbac.assertCanManageRoleLevel(actor, role.scope_level);
    this.rbac.assertNoEscalation(actor, (await this.rbac.rolePermissions(role.role_id)).map((p) => p.permission_code));
  }

  private async findAssignmentView(itsId: string, roleId: string, scopeId: string | null) {
    const match = (await this.rbac.allAssignments(itsId)).find((a) => a.role_id === roleId && a.scope_id === scopeId);
    return match ? { its_id: itsId, ...publicAssignment(match) } : null;
  }

  private async loadUser(actor: ActorContext, itsId: string): Promise<UserRow> {
    const user = await queryOne<UserRow>(this.db, `SELECT ${COLUMNS} FROM users WHERE its_id = $1`, [itsId]);
    if (!user) throw DomainError.notFound('User', itsId);
    this.rbac.assertTenant(actor, user.tenant_id, 'User', itsId);
    return user;
  }
}
