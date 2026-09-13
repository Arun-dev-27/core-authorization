import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { RecordStatus } from '@common/constants/rbac.constants';
import { DomainError } from '@common/errors/domain-error';
import { AuditService } from '@core/audit/audit.service';
import { queryMany, queryOne, returningRows } from '@core/database/sql';
import { AuthzCacheService } from '@modules/authorization/services/authz-cache.service';
import { RbacService } from '@modules/rbac/services/rbac.service';
import { ActorContext } from '@shared/types/principal.types';

export interface CreateBusinessUnitInput {
  name: string;
  status?: RecordStatus;
  tenant_id?: string;
}

export interface UpdateBusinessUnitInput {
  name?: string;
  status?: RecordStatus;
}

const COLUMNS = 'bu_id, tenant_id, name, status, created_at, updated_at';

@Injectable()
export class BusinessUnitsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly rbac: RbacService,
    private readonly audit: AuditService,
    private readonly cache: AuthzCacheService,
  ) {}

  /** CORE sees every BU of the tenant; a BU / utility workspace only sees its own BU. */
  list(actor: ActorContext, status?: RecordStatus) {
    return queryMany(
      this.db,
      `SELECT bu.bu_id, bu.tenant_id, bu.name, bu.status, bu.created_at, bu.updated_at,
              (SELECT count(*)::int FROM utilities u WHERE u.bu_id = bu.bu_id) AS utility_count
         FROM business_units bu
        WHERE ($1::uuid IS NULL OR bu.tenant_id = $1)
          AND ($2::uuid IS NULL OR bu.bu_id = $2)
          AND ($3::varchar IS NULL OR bu.status = $3)
        ORDER BY bu.name`,
      [actor.tenantId, actor.isCore ? null : actor.scopeBuId, status ?? null],
    );
  }

  async create(actor: ActorContext, input: CreateBusinessUnitInput) {
    if (!actor.isCore) throw new DomainError('SCOPE_NOT_PERMITTED', 'Only a CORE workspace can create business units', 403);
    const tenantId = await this.rbac.tenantForWrite(actor, input.tenant_id);
    const row = await queryOne<{ bu_id: string }>(
      this.db,
      `INSERT INTO business_units (tenant_id, name, status) VALUES ($1, $2, COALESCE($3, 'active')) RETURNING ${COLUMNS}`,
      [tenantId, input.name, input.status ?? null],
    );
    await this.audit.record({ eventType: 'BUSINESS_UNIT_CREATED', resourceType: 'business_unit', resourceId: row!.bu_id });
    return row;
  }

  async update(actor: ActorContext, buId: string, input: UpdateBusinessUnitInput) {
    await this.rbac.assertCanTargetScope(actor, 'BUSINESS_UNIT', buId);
    const [row] = returningRows(
      await this.db.query(`UPDATE business_units SET name = COALESCE($2, name), status = COALESCE($3, status) WHERE bu_id = $1 RETURNING ${COLUMNS}`, [
        buId,
        input.name ?? null,
        input.status ?? null,
      ]),
    );
    await this.cache.invalidateAll();
    await this.audit.record({ eventType: 'BUSINESS_UNIT_UPDATED', resourceType: 'business_unit', resourceId: buId, metadata: { fields: Object.keys(input) } });
    return row;
  }
}
