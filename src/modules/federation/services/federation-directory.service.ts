import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { ScopeLevel } from '@common/constants/rbac.constants';
import { DomainError } from '@common/errors/domain-error';
import { queryMany, queryOne } from '@core/database/sql';
import { RbacService } from '@modules/rbac/services/rbac.service';

interface LauncherRow {
  application_code: string;
  application_name: string;
  business_unit: string | null;
  utility: string | null;
  environment: string;
  client_id: string | null;
  initiate_login_uri: string | null;
  roles: { code: string; name: string }[];
}

/** Read models for Identity Federation (Core Portal): workspaces, their permissions and launchable applications. */
@Injectable()
export class FederationDirectoryService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly rbac: RbacService,
    private readonly config: AppConfig,
  ) {}

  async assignments(itsId: string) {
    const user = await queryOne<{ name: string }>(this.db, `SELECT name FROM users WHERE its_id = $1 AND status = 'active'`, [itsId]);
    const assignments = user ? (await this.rbac.listAssignments(itsId)).map((a) => this.rbac.toActiveScope(a)) : [];
    return { its_id: itsId, name: user?.name ?? null, requires_scope_selection: assignments.length > 1, assignments };
  }

  /** Validates a workspace choice (POST /select-scope) and returns it with its permission map. */
  async resolve(input: { its_id: string; role_id: string; scope_type: ScopeLevel; scope_id?: string | null }) {
    const assignment = await this.rbac.findAssignment(input.its_id, input.role_id, input.scope_type, input.scope_id ?? null);
    if (!assignment) throw new DomainError('ASSIGNMENT_NOT_FOUND', 'This workspace is not assigned to the user', 404);
    return { active_scope: this.rbac.toActiveScope(assignment), permissions: await this.rbac.permissionMap(assignment.role_id) };
  }

  /** Applications the user can open in one environment: an active client + at least one permission via a covering assignment. */
  async launchableApplications(itsId: string, environment: string) {
    const rows = await queryMany<LauncherRow>(
      this.db,
      `WITH assignment AS (
         SELECT ur.role_id, r.role_name, ur.scope_type, ur.scope_id
           FROM user_roles ur
           JOIN users u ON u.its_id = ur.its_id AND u.status = 'active'
           JOIN roles r ON r.role_id = ur.role_id AND r.tenant_id = u.tenant_id
           LEFT JOIN business_units bu ON ur.scope_type = 'BUSINESS_UNIT' AND bu.bu_id = ur.scope_id AND bu.status = 'active'
           LEFT JOIN utilities ut ON ur.scope_type = 'UTILITY' AND ut.utility_id = ur.scope_id AND ut.status = 'active'
          WHERE ur.its_id = $1 AND (ur.scope_type = 'CORE' OR bu.bu_id IS NOT NULL OR ut.utility_id IS NOT NULL)
       )
       SELECT a.code AS application_code, a.name AS application_name, obu.name AS business_unit, aut.name AS utility,
              e.code AS environment, c.client_id, c.initiate_login_uri,
              json_agg(DISTINCT jsonb_build_object('code', asg.role_id, 'name', asg.role_name)) AS roles
         FROM applications a
         JOIN users owner_user ON owner_user.its_id = $1 AND owner_user.tenant_id = a.tenant_id
         JOIN environments e ON e.code = $2
         LEFT JOIN utilities aut ON aut.utility_id = a.utility_id
         LEFT JOIN business_units obu ON obu.bu_id = COALESCE(a.bu_id, aut.bu_id)
         JOIN assignment asg ON asg.scope_type = 'CORE'
                             OR (asg.scope_type = 'BUSINESS_UNIT' AND asg.scope_id = COALESCE(a.bu_id, aut.bu_id))
                             OR (asg.scope_type = 'UTILITY' AND asg.scope_id = a.utility_id)
         JOIN role_permissions rp ON rp.role_id = asg.role_id
         JOIN permissions p ON p.permission_id = rp.permission_id
         JOIN modules m ON m.module_id = p.module_id AND (m.application_id = a.application_id OR (a.code = $3 AND m.application_id IS NULL))
         LEFT JOIN LATERAL (
              SELECT client_id, initiate_login_uri FROM clients
               WHERE application_id = a.application_id AND environment_id = e.id AND status = 'ACTIVE'
               ORDER BY CASE client_type WHEN 'WEB' THEN 0 WHEN 'SPA' THEN 1 ELSE 2 END, client_id
               LIMIT 1
         ) c ON true
        WHERE a.status = 'active'
          AND (obu.bu_id IS NULL OR obu.status = 'active')
          AND (aut.utility_id IS NULL OR aut.status = 'active')
        GROUP BY a.application_id, a.code, a.name, obu.name, aut.name, e.code, c.client_id, c.initiate_login_uri
        ORDER BY a.name`,
      [itsId, environment, this.config.env.CORE_PORTAL_APPLICATION_CODE],
    );
    return rows.map((r) => ({ ...r, roles: [...r.roles].sort((x, y) => x.name.localeCompare(y.name)), launchable: Boolean(r.client_id && r.initiate_login_uri) }));
  }
}
