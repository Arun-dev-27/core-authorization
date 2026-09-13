import { DEFAULT_MODULES, PermissionAction, permissionCode, ScopeLevel } from '@common/constants/rbac.constants';
import { Queryable } from '@core/database/sql';

/** Default roles (MIQAAT CORE — Role & Permission Module, section 2). Column order of the matrix below. */
export const SYSTEM_ROLES: readonly { name: string; level: ScopeLevel }[] = [
  { name: 'Platform Administrator', level: 'CORE' },
  { name: 'Business Unit Admin', level: 'BUSINESS_UNIT' },
  { name: 'BU Sub-Level Admin', level: 'BUSINESS_UNIT' },
  { name: 'Utility Admin', level: 'UTILITY' },
  { name: 'Utility Sub-Level Admin', level: 'UTILITY' },
];

/** Actions seeded for every default module (section 4 uses V, C, E, A; delete/export are open items). */
export const DEFAULT_MODULE_ACTIONS: readonly PermissionAction[] = ['view', 'create', 'edit', 'approve'];

const row = (core: string, bu: string, buSub: string, utility: string, utilitySub: string) => [core, bu, buSub, utility, utilitySub];

/** Section 4 permissions matrix: V = view, C = create, E = edit, A = approve; blank = no access. */
export const PERMISSION_MATRIX: Record<string, string[]> = {
  DASHBOARD: row('V', 'V', 'V', 'V', 'V'),
  BUSINESS_UNIT_MGMT: row('VCE', '', '', '', ''),
  UTILITY_MGMT: row('VCE', '', '', '', ''),
  ROLE_MGMT: row('VCE', 'VCE', '', 'VCE', ''),
  USER_MGMT: row('VCE', 'VCE', 'VE', 'VCE', 'VE'),
  MUMIN_INFO: row('V', '', '', '', ''),
  EVENT_CONTRACT: row('VCEA', 'VCA', 'VC', 'VCA', 'VC'),
  API_CONTRACT: row('VCEA', 'VCA', 'VC', 'VCA', 'VC'),
  CONTRACT_LIBRARY: row('', 'V', 'V', 'V', 'V'),
  ACCESS_REQUEST: row('VCEA', 'VCA', 'VC', 'VCA', 'VC'),
  TICKET_MGMT: row('VCE', 'VCE', 'VC', 'VCE', 'VC'),
  MONITORING: row('V', 'V', 'V', 'V', 'V'),
  AUDIT_LOG: row('V', 'V', '', 'V', ''),
  CONFIGURATION: row('VE', 'VE', '', 'VE', ''),
};

const LETTERS: Record<string, PermissionAction> = { V: 'view', C: 'create', E: 'edit', A: 'approve' };

export function matrixPermissionCodes(roleIndex: number): string[] {
  return Object.entries(PERMISSION_MATRIX).flatMap(([module, cells]) => [...cells[roleIndex]].map((letter) => permissionCode(module, LETTERS[letter])));
}

async function one<T>(db: Queryable, sql: string, params: unknown[]): Promise<T> {
  return ((await db.query(sql, params)) as T[])[0];
}

/**
 * Idempotently seeds the tenant, the 14 default modules with their permissions and the 5 system roles with
 * exactly the matrix permissions (matrix is authoritative for default modules on system roles).
 */
export async function seedCoreRbac(db: Queryable, tenantName: string): Promise<{ tenantId: string; roles: Record<string, string> }> {
  const tenant = await one<{ tenant_id: string }>(
    db,
    `INSERT INTO tenants (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING tenant_id`,
    [tenantName],
  );

  for (const module of DEFAULT_MODULES) {
    const mod = await one<{ module_id: string }>(
      db,
      `INSERT INTO modules (module_code, module_name, is_default) VALUES ($1, $2, true)
       ON CONFLICT (module_code) DO UPDATE SET module_name = EXCLUDED.module_name, is_default = true RETURNING module_id`,
      [module.code, module.name],
    );
    for (const action of DEFAULT_MODULE_ACTIONS) {
      await db.query(`INSERT INTO permissions (module_id, action, permission_code) VALUES ($1, $2, $3) ON CONFLICT (permission_code) DO NOTHING`, [
        mod.module_id,
        action,
        permissionCode(module.code, action),
      ]);
    }
  }

  const roles: Record<string, string> = {};
  for (const [index, role] of SYSTEM_ROLES.entries()) {
    const saved = await one<{ role_id: string }>(
      db,
      `INSERT INTO roles (tenant_id, role_name, scope_level, is_system_role) VALUES ($1, $2, $3, true)
       ON CONFLICT (tenant_id, role_name) DO UPDATE SET scope_level = EXCLUDED.scope_level, is_system_role = true RETURNING role_id`,
      [tenant.tenant_id, role.name, role.level],
    );
    const codes = matrixPermissionCodes(index);
    await db.query(
      `DELETE FROM role_permissions rp USING permissions p, modules m
        WHERE rp.permission_id = p.permission_id AND p.module_id = m.module_id AND m.is_default
          AND rp.role_id = $1 AND NOT (p.permission_code = ANY($2))`,
      [saved.role_id, codes],
    );
    await db.query(
      `INSERT INTO role_permissions (role_id, permission_id) SELECT $1, permission_id FROM permissions WHERE permission_code = ANY($2) ON CONFLICT DO NOTHING`,
      [saved.role_id, codes],
    );
    roles[role.name] = saved.role_id;
  }
  return { tenantId: tenant.tenant_id, roles };
}
