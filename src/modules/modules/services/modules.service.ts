import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { actionRank, moduleRank, PermissionAction, permissionCode } from '@common/constants/rbac.constants';
import { DomainError } from '@common/errors/domain-error';
import { AuditService } from '@core/audit/audit.service';
import { queryMany, queryOne } from '@core/database/sql';
import { AuthzCacheService } from '@modules/authorization/services/authz-cache.service';
import { RbacService } from '@modules/rbac/services/rbac.service';

export interface CreateModuleInput {
  module_code: string;
  module_name: string;
  application_code?: string;
  actions?: PermissionAction[];
}

export interface CreatePermissionInput {
  module_code: string;
  action: PermissionAction;
}

interface ModuleRow {
  module_id: string;
  module_code: string;
  module_name: string;
  is_default: boolean;
  application_code: string | null;
  permissions: { permission_id: string; action: string; permission_code: string }[];
}

@Injectable()
export class ModulesService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly rbac: RbacService,
    private readonly audit: AuditService,
    private readonly cache: AuthzCacheService,
  ) {}

  async listModules(query: { application_code?: string; is_default?: 'true' | 'false'; module_code?: string }) {
    const rows = await queryMany<ModuleRow>(
      this.db,
      `SELECT m.module_id, m.module_code, m.module_name, m.is_default, a.code AS application_code, m.created_at, m.updated_at,
              COALESCE(json_agg(json_build_object('permission_id', p.permission_id, 'action', p.action, 'permission_code', p.permission_code))
                       FILTER (WHERE p.permission_id IS NOT NULL), '[]') AS permissions
         FROM modules m
         LEFT JOIN applications a ON a.application_id = m.application_id
         LEFT JOIN permissions p ON p.module_id = m.module_id
        WHERE ($1::varchar IS NULL OR a.code = $1)
          AND ($2::boolean IS NULL OR m.is_default = $2)
          AND ($3::varchar IS NULL OR m.module_code = $3)
        GROUP BY m.module_id, a.code`,
      [query.application_code ?? null, query.is_default === undefined ? null : query.is_default === 'true', query.module_code ?? null],
    );
    for (const row of rows) row.permissions.sort((x, y) => actionRank(x.action) - actionRank(y.action));
    return rows.sort(
      (x, y) =>
        Number(y.is_default) - Number(x.is_default) ||
        moduleRank(x.module_code) - moduleRank(y.module_code) ||
        (x.application_code ?? '').localeCompare(y.application_code ?? '') ||
        x.module_code.localeCompare(y.module_code),
    );
  }

  async createModule(input: CreateModuleInput) {
    const app = input.application_code ? await this.rbac.applicationByCode(input.application_code) : null;
    const actions = [...new Set(input.actions?.length ? input.actions : (['view'] as PermissionAction[]))];
    await this.db.transaction(async (tx) => {
      const mod = await queryOne<{ module_id: string }>(
        tx,
        `INSERT INTO modules (module_code, module_name, is_default, application_id) VALUES ($1, $2, false, $3) RETURNING module_id`,
        [input.module_code, input.module_name, app?.id ?? null],
      );
      for (const action of actions) {
        await tx.query(`INSERT INTO permissions (module_id, action, permission_code) VALUES ($1, $2, $3)`, [mod!.module_id, action, permissionCode(input.module_code, action)]);
      }
    });
    await this.cache.invalidateAll();
    await this.audit.record({ eventType: 'MODULE_CREATED', resourceType: 'module', resourceId: input.module_code, metadata: { application: app?.code ?? null, actions } });
    return (await this.listModules({ module_code: input.module_code }))[0];
  }

  listPermissions(query: { module_code?: string }) {
    return queryMany(
      this.db,
      `SELECT p.permission_id, p.permission_code, p.action, m.module_id, m.module_code, m.is_default, p.created_at, p.updated_at
         FROM permissions p JOIN modules m ON m.module_id = p.module_id
        WHERE ($1::varchar IS NULL OR m.module_code = $1)
        ORDER BY m.module_code, p.permission_code`,
      [query.module_code ?? null],
    );
  }

  async createPermission(input: CreatePermissionInput) {
    const mod = await queryOne<{ module_id: string }>(this.db, `SELECT module_id FROM modules WHERE module_code = $1`, [input.module_code]);
    if (!mod) throw DomainError.notFound('Module', input.module_code);
    const code = permissionCode(input.module_code, input.action);
    const row = await queryOne(
      this.db,
      `INSERT INTO permissions (module_id, action, permission_code) VALUES ($1, $2, $3)
       RETURNING permission_id, permission_code, action, module_id, created_at, updated_at`,
      [mod.module_id, input.action, code],
    );
    await this.cache.invalidateAll();
    await this.audit.record({ eventType: 'PERMISSION_CREATED', resourceType: 'permission', resourceId: code });
    return row;
  }
}
