/** MIQAAT CORE — Role & Permission Module constants (see docs/data-model.md). */

export const SCOPE_LEVELS = ['CORE', 'BUSINESS_UNIT', 'UTILITY'] as const;
export type ScopeLevel = (typeof SCOPE_LEVELS)[number];

export const PERMISSION_ACTIONS = ['view', 'create', 'edit', 'delete', 'approve', 'export'] as const;
export type PermissionAction = (typeof PERMISSION_ACTIONS)[number];

export const RECORD_STATUSES = ['active', 'inactive'] as const;
export type RecordStatus = (typeof RECORD_STATUSES)[number];

export const USER_STATUSES = ['active', 'inactive', 'suspended'] as const;
export type UserStatus = (typeof USER_STATUSES)[number];

/** The 14 default Core modules, in sidebar order. */
export const DEFAULT_MODULES = [
  { code: 'DASHBOARD', name: 'Dashboard' },
  { code: 'BUSINESS_UNIT_MGMT', name: 'Business Unit Management' },
  { code: 'UTILITY_MGMT', name: 'Utility Management' },
  { code: 'ROLE_MGMT', name: 'Role Management' },
  { code: 'USER_MGMT', name: 'User Management' },
  { code: 'MUMIN_INFO', name: 'Mumin Information' },
  { code: 'EVENT_CONTRACT', name: 'Event Contracts' },
  { code: 'API_CONTRACT', name: 'API Contracts' },
  { code: 'CONTRACT_LIBRARY', name: 'Contract Library' },
  { code: 'ACCESS_REQUEST', name: 'Access Requests' },
  { code: 'TICKET_MGMT', name: 'Ticket Management' },
  { code: 'MONITORING', name: 'Monitoring' },
  { code: 'AUDIT_LOG', name: 'Audit Log' },
  { code: 'CONFIGURATION', name: 'Configuration' },
] as const;

export function permissionCode(moduleCode: string, action: string): string {
  return `${moduleCode}_${action.toUpperCase()}`;
}

export function actionRank(action: string): number {
  const i = (PERMISSION_ACTIONS as readonly string[]).indexOf(action);
  return i === -1 ? PERMISSION_ACTIONS.length : i;
}

export function moduleRank(moduleCode: string): number {
  const i = DEFAULT_MODULES.findIndex((m) => m.code === moduleCode);
  return i === -1 ? DEFAULT_MODULES.length : i;
}

/** Role scope levels an actor may create or assign ("Can create sub-roles?"). */
export function manageableLevels(actorScope: ScopeLevel): ScopeLevel[] {
  if (actorScope === 'CORE') return ['CORE', 'BUSINESS_UNIT', 'UTILITY'];
  if (actorScope === 'BUSINESS_UNIT') return ['BUSINESS_UNIT', 'UTILITY'];
  return ['UTILITY'];
}
