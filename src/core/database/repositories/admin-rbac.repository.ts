import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, Repository } from 'typeorm';
import { AdminUser } from '../entities/admin/admin-user.entity';
import type { RoleLevel } from '../entities/admin/admin-rbac.enums';
import { RolePermission } from '../entities/admin/role-permission.entity';
import { UserRole } from '../entities/admin/user-role.entity';
import { UserSession } from '../entities/admin/user-session.entity';

export interface NewUserSession {
  userId: string;
  roleId: string;
  coreSid: string | null;
  aud: string | null;
  sessionToken: string;
  ipAddress: string | null;
  userAgent: string | null;
  expiresAt: Date;
}

/**
 * The EXISTING admin_db RBAC data, as the Core Admin session flow needs it.
 *
 * Reads users, user_roles, roles, tenants, role_permissions, module_actions, modules and permission_actions exactly
 * as they are - it has no method that creates or changes a user, role, tenant, module or permission. Its only writes
 * are a user_sessions row per sign-in and the login bookkeeping on users.
 */
@Injectable()
export class AdminRbacRepository {
  constructor(
    @InjectRepository(AdminUser) private readonly users: Repository<AdminUser>,
    @InjectRepository(UserRole) private readonly userRoles: Repository<UserRole>,
    @InjectRepository(RolePermission) private readonly rolePermissions: Repository<RolePermission>,
    @InjectRepository(UserSession) private readonly sessions: Repository<UserSession>,
  ) {}

  /** identity_db users.mumin_id -> admin_db users.its_id. */
  findUserByItsId(itsId: string): Promise<AdminUser | null> {
    return this.users.findOne({ where: { itsId }, select: { id: true, itsId: true, name: true, email: true, status: true } });
  }

  /**
   * The user's role assignments whose role is ACTIVE, with role and tenant loaded. A role in an INACTIVE tenant is
   * dropped; the tenant-less CORE_ADMIN role is kept. Pass roleId to re-check one specific assignment.
   */
  async findActiveAssignments(userId: string, roleId?: string): Promise<UserRole[]> {
    const assignments = await this.userRoles.find({
      where: { userId, ...(roleId ? { roleId } : {}), role: { status: 'ACTIVE' } },
      relations: { role: { tenant: true } },
    });
    return assignments.filter((a) => a.role.tenant === null || a.role.tenant.status === 'ACTIVE');
  }

  /** First successful sign-in flips INVITED -> ACTIVE; every sign-in stamps last_login_at and has_been_active. */
  async recordLogin(userId: string): Promise<void> {
    await this.users
      .createQueryBuilder()
      .update(AdminUser)
      .set({
        lastLoginAt: () => 'now()',
        hasBeenActive: true,
        status: () => `CASE WHEN status = 'INVITED' THEN 'ACTIVE' ELSE status END`,
      })
      .where('id = :userId', { userId })
      .execute();
  }

  async createSession(session: NewUserSession): Promise<void> {
    await this.sessions.insert(session);
  }

  /** The session with its user, role and the role's tenant - everything a request needs to be authorized. */
  findSession(sessionToken: string): Promise<UserSession | null> {
    return this.sessions.findOne({ where: { sessionToken }, relations: { user: true, role: { tenant: true } } });
  }

  async revokeSession(sessionToken: string): Promise<void> {
    await this.sessions.update({ sessionToken, revokedAt: IsNull() }, { revokedAt: () => 'now()' });
  }

  /**
   * (module code, action code) pairs granted to the role, lower-cased - only those the module AND the module action
   * offer at the role's level (core vs tenant).
   */
  async grantedModuleActions(roleId: string, roleLevel: RoleLevel): Promise<{ module: string; action: string }[]> {
    const level = roleLevel === 'CORE_ADMIN' ? 'Core' : 'Tenant';
    return this.rolePermissions
      .createQueryBuilder('rp')
      .innerJoin('rp.moduleAction', 'ma')
      .innerJoin('ma.module', 'm')
      .innerJoin('ma.action', 'a')
      .select('LOWER(m.code)', 'module')
      .addSelect('LOWER(a.code)', 'action')
      .where('rp.roleId = :roleId', { roleId })
      .andWhere(`m.appliesTo${level} = true`)
      .andWhere(`ma.appliesTo${level} = true`)
      .getRawMany<{ module: string; action: string }>();
  }
}
