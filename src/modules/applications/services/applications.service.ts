import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { RecordStatus } from '@common/constants/rbac.constants';
import { DomainError } from '@common/errors/domain-error';
import { AuditService } from '@core/audit/audit.service';
import { queryMany, queryOne } from '@core/database/sql';
import { AuthzCacheService } from '@modules/authorization/services/authz-cache.service';
import { RbacService } from '@modules/rbac/services/rbac.service';
import { ActorContext } from '@shared/types/principal.types';

export interface CreateApplicationInput {
  code: string;
  name: string;
  description?: string;
  bu_id?: string;
  utility_id?: string;
  status?: RecordStatus;
}

@Injectable()
export class ApplicationsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly rbac: RbacService,
    private readonly audit: AuditService,
    private readonly cache: AuthzCacheService,
  ) {}

  list(actor: ActorContext, status?: RecordStatus) {
    return queryMany(
      this.db,
      `SELECT a.application_id, a.tenant_id, a.code, a.name, a.description, a.status,
              a.bu_id, bu.name AS bu_name, a.utility_id, ut.name AS utility_name, a.created_at, a.updated_at
         FROM applications a
         LEFT JOIN business_units bu ON bu.bu_id = a.bu_id
         LEFT JOIN utilities ut ON ut.utility_id = a.utility_id
        WHERE ($1::uuid IS NULL OR a.tenant_id = $1) AND ($2::varchar IS NULL OR a.status = $2)
        ORDER BY a.code`,
      [actor.tenantId, status ?? null],
    );
  }

  /** Owner: a business unit, a utility, or neither (tenant-level, e.g. Core Portal). */
  async create(actor: ActorContext, input: CreateApplicationInput) {
    if (input.bu_id && input.utility_id) throw new DomainError('APPLICATION_SINGLE_OWNER', 'An application belongs to a business unit or a utility, not both');
    const tenantId = await this.rbac.tenantForWrite(actor);
    const owner = input.bu_id
      ? await this.rbac.assertCanTargetScope(actor, 'BUSINESS_UNIT', input.bu_id)
      : input.utility_id
        ? await this.rbac.assertCanTargetScope(actor, 'UTILITY', input.utility_id)
        : null;
    if (owner && owner.tenant_id !== tenantId) throw new DomainError('TENANT_MISMATCH', 'The owner belongs to a different tenant');
    const row = await queryOne<{ application_id: string }>(
      this.db,
      `INSERT INTO applications (tenant_id, bu_id, utility_id, code, name, description, status)
       VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, 'active'))
       RETURNING application_id, tenant_id, bu_id, utility_id, code, name, description, status, created_at, updated_at`,
      [tenantId, input.bu_id ?? null, input.utility_id ?? null, input.code, input.name, input.description ?? null, input.status ?? null],
    );
    await this.cache.invalidateAll();
    await this.audit.record({ eventType: 'APPLICATION_CREATED', resourceType: 'application', resourceId: input.code });
    return row;
  }
}
