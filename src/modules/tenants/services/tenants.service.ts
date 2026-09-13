import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { RecordStatus } from '@common/constants/rbac.constants';
import { DomainError } from '@common/errors/domain-error';
import { AuditService } from '@core/audit/audit.service';
import { queryMany, queryOne, returningRows } from '@core/database/sql';
import { AuthzCacheService } from '@modules/authorization/services/authz-cache.service';

export interface TenantInput {
  name: string;
  status?: RecordStatus;
}

const COLUMNS = 'tenant_id, name, status, created_at, updated_at';

@Injectable()
export class TenantsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly audit: AuditService,
    private readonly cache: AuthzCacheService,
  ) {}

  list() {
    return queryMany(this.db, `SELECT ${COLUMNS} FROM tenants ORDER BY name`);
  }

  async create(input: TenantInput) {
    const row = await queryOne<{ tenant_id: string }>(
      this.db,
      `INSERT INTO tenants (name, status) VALUES ($1, COALESCE($2, 'active')) RETURNING ${COLUMNS}`,
      [input.name, input.status ?? null],
    );
    await this.audit.record({ eventType: 'TENANT_CREATED', resourceType: 'tenant', resourceId: row!.tenant_id });
    return row;
  }

  async update(tenantId: string, input: Partial<TenantInput>) {
    const [row] = returningRows<{ tenant_id: string }>(
      await this.db.query(`UPDATE tenants SET name = COALESCE($2, name), status = COALESCE($3, status) WHERE tenant_id = $1 RETURNING ${COLUMNS}`, [
        tenantId,
        input.name ?? null,
        input.status ?? null,
      ]),
    );
    if (!row) throw DomainError.notFound('Tenant', tenantId);
    await this.cache.invalidateAll();
    await this.audit.record({ eventType: 'TENANT_UPDATED', resourceType: 'tenant', resourceId: tenantId, metadata: { fields: Object.keys(input) } });
    return row;
  }
}
