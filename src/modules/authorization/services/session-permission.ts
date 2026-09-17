/**
 * The decision behind POST /authorization/session/check, as a pure function over the session's live state.
 *
 * Inputs are read fresh from the RBAC tables on every check (not from login time), so a user disabled, a
 * role deactivated or a tenant switched off after sign-in loses access immediately.
 *
 *   1. user     users.status must be ACTIVE
 *   2. role     roles.status must be ACTIVE
 *   3. tenant   a tenant-scoped role's tenant must be ACTIVE
 *   4. isolation a tenant-scoped role may only act inside its own tenant; the CORE_ADMIN role is platform-wide
 *   5. module + action granted through role_permissions (module_actions x permission_actions)
 */

export type RoleLevel = 'CORE_ADMIN' | 'BUSINESS_UNIT_ADMIN' | 'UTILITY_ADMIN';

export type SessionPermissionDenial =
  | 'USER_NOT_ACTIVE'
  | 'ROLE_NOT_ACTIVE'
  | 'TENANT_NOT_ACTIVE'
  | 'TENANT_MISMATCH'
  | 'MODULE_NOT_GRANTED'
  | 'ACTION_NOT_GRANTED';

export interface SessionPermissionState {
  userStatus: string;
  roleStatus: string;
  roleLevel: RoleLevel;
  roleTenantId: string | null;
  tenantStatus: string | null;
  /** lower-case module code -> lower-case action code -> granted, as returned by getModulePermissions. */
  permissions: Record<string, Record<string, boolean>>;
}

export interface SessionPermissionRequest {
  module: string;
  action: string;
  /** Tenant the operation targets; omitted means "the session's own scope". */
  tenantId?: string | null;
}

export type SessionPermissionDecision = { allowed: true } | { allowed: false; reason: SessionPermissionDenial };

export function decideSessionPermission(state: SessionPermissionState, request: SessionPermissionRequest): SessionPermissionDecision {
  if (state.userStatus !== 'ACTIVE') return { allowed: false, reason: 'USER_NOT_ACTIVE' };
  if (state.roleStatus !== 'ACTIVE') return { allowed: false, reason: 'ROLE_NOT_ACTIVE' };
  if (state.roleTenantId !== null && state.tenantStatus !== 'ACTIVE') return { allowed: false, reason: 'TENANT_NOT_ACTIVE' };

  if (request.tenantId && state.roleLevel !== 'CORE_ADMIN' && request.tenantId.toLowerCase() !== state.roleTenantId?.toLowerCase()) {
    return { allowed: false, reason: 'TENANT_MISMATCH' };
  }

  const actions = state.permissions[request.module.toLowerCase()];
  if (!actions) return { allowed: false, reason: 'MODULE_NOT_GRANTED' };
  if (actions[request.action.toLowerCase()] !== true) return { allowed: false, reason: 'ACTION_NOT_GRANTED' };
  return { allowed: true };
}
