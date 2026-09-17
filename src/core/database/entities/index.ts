import { getMetadataArgsStorage } from 'typeorm';
import { AdminUser } from './admin/admin-user.entity';
import { CoreModule } from './admin/core-module.entity';
import { ModuleAction } from './admin/module-action.entity';
import { PermissionAction } from './admin/permission-action.entity';
import { RolePermission } from './admin/role-permission.entity';
import { Role } from './admin/role.entity';
import { Tenant } from './admin/tenant.entity';
import { UserRole } from './admin/user-role.entity';
import { UserSession } from './admin/user-session.entity';

export { AdminUser, CoreModule, ModuleAction, PermissionAction, Role, RolePermission, Tenant, UserRole, UserSession };

/** The EXISTING admin_db RBAC tables this service reads (and user_sessions / users login bookkeeping it writes). */
export const ADMIN_DB_ENTITIES = [AdminUser, Tenant, Role, UserRole, CoreModule, PermissionAction, ModuleAction, RolePermission, UserSession];

/**
 * Points the admin_db entities at AUTHZ_DB_SCHEMA (`public` in admin_db).
 *
 * Set per entity rather than as the DataSource `schema` option on purpose: that option would also move TypeORM's
 * migrations ledger, which this service's own (optional, non-admin_db) migrations depend on. Every entity query
 * is therefore schema-qualified, e.g. "public"."users".
 */
export function useAdminSchema(schema: string): void {
  const targets = new Set<unknown>(ADMIN_DB_ENTITIES);
  for (const table of getMetadataArgsStorage().tables) {
    if (targets.has(table.target)) table.schema = schema;
  }
}
