import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { RecordStatus } from '@common/constants/rbac.constants';
import { AuditService } from '@core/audit/audit.service';
import { queryMany, queryOne, returningRows } from '@core/database/sql';
import { AuthzCacheService } from '@modules/authorization/services/authz-cache.service';
import { RbacService } from '@modules/rbac/services/rbac.service';
import { ActorContext } from '@shared/types/principal.types';

export interface CreateUtilityInput {
  bu_id: string;
  name: string;
  status?: RecordStatus;
}

export interface UpdateUtilityInput {
  name?: string;
  status?: RecordStatus;
}

const COLUMNS = 'utility_id, bu_id, name, status, created_at, updated_at';

@Injectable()
export class UtilitiesService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly rbac: RbacService,
    private readonly audit: AuditService,
    private readonly cache: AuthzCacheService,
  ) {}

  /** CORE: all utilities of the tenant; BU workspace: utilities of its BU; utility workspace: its own utility. */
  list(actor: ActorContext, query: { bu_id?: string; status?: RecordStatus }) {
    return queryMany(
      this.db,
      `SELECT u.utility_id, u.bu_id, bu.name AS bu_name, u.name, u.status, u.created_at, u.updated_at
         FROM utilities u
         JOIN business_units bu ON bu.bu_id = u.bu_id
        WHERE ($1::uuid IS NULL OR bu.tenant_id = $1)
          AND ($2::uuid IS NULL OR u.bu_id = $2)
          AND ($3::uuid IS NULL OR u.bu_id = $3)
          AND ($4::uuid IS NULL OR u.utility_id = $4)
          AND ($5::varchar IS NULL OR u.status = $5)
        ORDER BY bu.name, u.name`,
      [
        actor.tenantId,
        query.bu_id ?? null,
        actor.isCore ? null : actor.scopeBuId,
        !actor.isCore && actor.scopeType === 'UTILITY' ? actor.scopeId : null,
        query.status ?? null,
      ],
    );
  }

  async create(actor: ActorContext, input: CreateUtilityInput) {
    await this.rbac.assertCanTargetScope(actor, 'BUSINESS_UNIT', input.bu_id);
    const row = await queryOne<{ utility_id: string }>(
      this.db,
      `INSERT INTO utilities (bu_id, name, status) VALUES ($1, $2, COALESCE($3, 'active')) RETURNING ${COLUMNS}`,
      [input.bu_id, input.name, input.status ?? null],
    );
    await this.audit.record({ eventType: 'UTILITY_CREATED', resourceType: 'utility', resourceId: row!.utility_id, metadata: { bu_id: input.bu_id } });
    return row;
  }

  async update(actor: ActorContext, utilityId: string, input: UpdateUtilityInput) {
    await this.rbac.assertCanTargetScope(actor, 'UTILITY', utilityId);
    const [row] = returningRows(
      await this.db.query(`UPDATE utilities SET name = COALESCE($2, name), status = COALESCE($3, status) WHERE utility_id = $1 RETURNING ${COLUMNS}`, [
        utilityId,
        input.name ?? null,
        input.status ?? null,
      ]),
    );
    await this.cache.invalidateAll();
    await this.audit.record({ eventType: 'UTILITY_UPDATED', resourceType: 'utility', resourceId: utilityId, metadata: { fields: Object.keys(input) } });
    return row;
  }
}
