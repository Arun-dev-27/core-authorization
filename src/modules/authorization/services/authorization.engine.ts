import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { ScopeLevel } from '@common/constants/rbac.constants';
import { queryMany, queryOne } from '@core/database/sql';
import { AuthzCacheService } from './authz-cache.service';

export type DenyReason =
  | 'CLIENT_NOT_FOUND'
  | 'CLIENT_NOT_ACTIVE'
  | 'APPLICATION_INACTIVE'
  | 'USER_NOT_FOUND'
  | 'USER_INACTIVE'
  | 'APPLICATION_ACCESS_DENIED'
  | 'PERMISSION_DENIED'
  | 'MODULE_MISMATCH';

export interface EffectiveRole {
  role_id: string;
  role_name: string;
  scope_type: ScopeLevel;
  scope_id: string | null;
}

export interface EffectiveAccess {
  its_id: string;
  client_id: string;
  access: 'GRANTED' | 'DENIED';
  reason?: DenyReason;
  application?: { code: string; name: string };
  environment?: string;
  business_unit?: string | null;
  utility?: string | null;
  roles: EffectiveRole[];
  modules: { code: string; name: string; permissions: string[] }[];
  permissions: string[];
  evaluated_at: string;
}

interface ContextRow {
  client_status: string;
  application_id: string;
  app_code: string;
  app_name: string;
  app_status: string;
  app_tenant: string;
  utility_id: string | null;
  owner_bu_id: string | null;
  bu_name: string | null;
  bu_status: string | null;
  ut_name: string | null;
  ut_status: string | null;
  env_code: string;
}

export interface GrantRow extends EffectiveRole {
  module_code: string;
  module_name: string;
  permission_code: string;
}

/**
 * Effective access of a user for one client (application + environment), from Core RBAC.
 *
 * Deny-by-default: client ACTIVE -> application and its BU / utility active -> user active in the
 * application's tenant -> roles whose assignment scope covers the application:
 *   CORE (whole tenant) | BUSINESS_UNIT = owning BU (also covers the BU's utilities) | UTILITY = owning utility
 * -> permissions of modules owned by this application (Core Portal: the default modules).
 */
@Injectable()
export class AuthorizationEngine {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly cache: AuthzCacheService,
    private readonly config: AppConfig,
  ) {}

  async evaluate(itsId: string, clientId: string): Promise<EffectiveAccess> {
    const cached = await this.cache.get<EffectiveAccess>(itsId, clientId);
    if (cached) return cached;
    const result = await this.compute(itsId, clientId);
    await this.cache.set(itsId, clientId, result);
    return result;
  }

  private async compute(itsId: string, clientId: string): Promise<EffectiveAccess> {
    const base = { its_id: itsId, client_id: clientId, roles: [], modules: [], permissions: [], evaluated_at: new Date().toISOString() };
    const deny = (reason: DenyReason, extra: Partial<EffectiveAccess> = {}): EffectiveAccess => ({ ...base, ...extra, access: 'DENIED', reason });

    const ctx = await queryOne<ContextRow>(
      this.db,
      `SELECT c.status AS client_status, a.application_id, a.code AS app_code, a.name AS app_name, a.status AS app_status,
              a.tenant_id AS app_tenant, a.utility_id, COALESCE(a.bu_id, aut.bu_id) AS owner_bu_id,
              obu.name AS bu_name, obu.status AS bu_status, aut.name AS ut_name, aut.status AS ut_status, e.code AS env_code
         FROM clients c
         JOIN applications a ON a.application_id = c.application_id
         JOIN environments e ON e.id = c.environment_id
         LEFT JOIN utilities aut ON aut.utility_id = a.utility_id
         LEFT JOIN business_units obu ON obu.bu_id = COALESCE(a.bu_id, aut.bu_id)
        WHERE c.client_id = $1`,
      [clientId],
    );
    if (!ctx) return deny('CLIENT_NOT_FOUND');

    const scope = {
      application: { code: ctx.app_code, name: ctx.app_name },
      environment: ctx.env_code,
      business_unit: ctx.bu_name,
      utility: ctx.ut_name,
    };
    if (ctx.client_status !== 'ACTIVE') return deny('CLIENT_NOT_ACTIVE', scope);
    if (ctx.app_status !== 'active' || (ctx.bu_status && ctx.bu_status !== 'active') || (ctx.ut_status && ctx.ut_status !== 'active')) {
      return deny('APPLICATION_INACTIVE', scope);
    }

    const user = await queryOne<{ status: string; tenant_id: string }>(this.db, `SELECT status, tenant_id FROM users WHERE its_id = $1`, [itsId]);
    if (!user) return deny('USER_NOT_FOUND', scope);
    if (user.status !== 'active') return deny('USER_INACTIVE', scope);
    if (user.tenant_id !== ctx.app_tenant) return deny('APPLICATION_ACCESS_DENIED', scope);

    const grants = await queryMany<GrantRow>(
      this.db,
      `SELECT ur.role_id, r.role_name, ur.scope_type, ur.scope_id, m.module_code, m.module_name, p.permission_code
         FROM user_roles ur
         JOIN roles r ON r.role_id = ur.role_id AND r.tenant_id = $3
         JOIN role_permissions rp ON rp.role_id = ur.role_id
         JOIN permissions p ON p.permission_id = rp.permission_id
         JOIN modules m ON m.module_id = p.module_id AND (m.application_id = $2 OR ($4::boolean AND m.application_id IS NULL))
        WHERE ur.its_id = $1
          AND (ur.scope_type = 'CORE'
               OR (ur.scope_type = 'BUSINESS_UNIT' AND ur.scope_id = $5::uuid)
               OR (ur.scope_type = 'UTILITY' AND ur.scope_id = $6::uuid))`,
      [itsId, ctx.application_id, ctx.app_tenant, ctx.app_code === this.config.env.CORE_PORTAL_APPLICATION_CODE, ctx.owner_bu_id, ctx.utility_id],
    );
    if (grants.length === 0) return deny('APPLICATION_ACCESS_DENIED', scope);

    return { ...base, ...scope, access: 'GRANTED', ...AuthorizationEngine.aggregate(grants) };
  }

  static aggregate(grants: GrantRow[]): Pick<EffectiveAccess, 'roles' | 'modules' | 'permissions'> {
    const roles = new Map<string, EffectiveRole>();
    const modules = new Map<string, { code: string; name: string; permissions: Set<string> }>();
    for (const g of grants) {
      roles.set(`${g.role_id}|${g.scope_id ?? ''}`, { role_id: g.role_id, role_name: g.role_name, scope_type: g.scope_type, scope_id: g.scope_id });
      const mod = modules.get(g.module_code) ?? { code: g.module_code, name: g.module_name, permissions: new Set<string>() };
      mod.permissions.add(g.permission_code);
      modules.set(g.module_code, mod);
    }
    const moduleList = [...modules.values()]
      .sort((a, b) => a.code.localeCompare(b.code))
      .map((m) => ({ code: m.code, name: m.name, permissions: [...m.permissions].sort() }));
    return {
      roles: [...roles.values()].sort((a, b) => a.role_name.localeCompare(b.role_name)),
      modules: moduleList,
      permissions: [...new Set(moduleList.flatMap((m) => m.permissions))].sort(),
    };
  }

  /** Pure decision for a single permission against an evaluated result. */
  static decide(effective: EffectiveAccess, permission: string, module?: string): { allowed: boolean; reason?: DenyReason } {
    if (effective.access === 'DENIED') return { allowed: false, reason: effective.reason };
    const owner = effective.modules.find((m) => m.permissions.includes(permission));
    if (!owner) return { allowed: false, reason: 'PERMISSION_DENIED' };
    if (module && owner.code !== module) return { allowed: false, reason: 'MODULE_MISMATCH' };
    return { allowed: true };
  }
}
