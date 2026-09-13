import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { requestContext } from '@common/logging/request-context';

export interface AuthorizationAuditEvent {
  eventType: string;
  itsId?: string | null;
  clientId?: string | null;
  resourceType?: string;
  resourceId?: string;
  decision?: 'ALLOW' | 'DENY';
  reason?: string;
  metadata?: Record<string, unknown>;
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  /** Best-effort: audit failures are logged but never break the business operation. */
  async record(event: AuthorizationAuditEvent): Promise<void> {
    const ctx = requestContext.getStore();
    try {
      await this.db.query(
        `INSERT INTO authorization_audit_logs
           (event_type, actor, its_id, client_id, resource_type, resource_id, decision, reason, correlation_id, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          event.eventType,
          ctx?.actor ?? 'system',
          event.itsId ?? null,
          event.clientId ?? null,
          event.resourceType ?? null,
          event.resourceId ?? null,
          event.decision ?? null,
          event.reason ?? null,
          ctx?.correlationId ?? null,
          event.metadata ? JSON.stringify(event.metadata) : null,
        ],
      );
    } catch (error) {
      this.logger.error({ msg: 'audit write failed', event_type: event.eventType, err: error });
    }
  }
}
