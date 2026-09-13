import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AuditService } from '@core/audit/audit.service';
import { queryMany } from '@core/database/sql';
import type { CreateEnvironmentInput } from './environments.types';

@Injectable()
export class EnvironmentsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly audit: AuditService,
  ) {}

  list() {
    return queryMany(this.db, `SELECT id, code, name, is_production, sort_order, created_at FROM environments ORDER BY sort_order, code`);
  }

  async create(dto: CreateEnvironmentInput) {
    const [row] = await queryMany<{ code: string }>(
      this.db,
      `INSERT INTO environments (code, name, is_production, sort_order) VALUES ($1, $2, $3, $4)
       RETURNING id, code, name, is_production, sort_order, created_at`,
      [dto.code, dto.name, dto.is_production ?? false, dto.sort_order ?? 0],
    );
    await this.audit.record({ eventType: 'ENVIRONMENT_CREATED', resourceType: 'environment', resourceId: row.code });
    return row;
  }
}
