import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { queryOne } from '@core/database/sql';

export interface ServicePrincipalRow {
  principal_id: string;
  name: string;
  jwks_uri: string;
  scopes: string[];
  allowed_client_ids: string[] | null;
  status: 'ACTIVE' | 'REVOKED';
}

const CACHE_TTL_MS = 60_000;
const LAST_USED_WRITE_INTERVAL_MS = 5 * 60_000;

/** Registry of calling services. Holds only public material (a JWKS URI), never secrets. */
@Injectable()
export class ServicePrincipalService {
  private readonly cache = new Map<string, { row: ServicePrincipalRow | null; at: number }>();
  private readonly lastUsed = new Map<string, number>();

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  async find(principalId: string): Promise<ServicePrincipalRow | null> {
    const hit = this.cache.get(principalId);
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.row;
    const row = await queryOne<ServicePrincipalRow>(
      this.db,
      `SELECT principal_id, name, jwks_uri, scopes, allowed_client_ids, status FROM service_principals WHERE principal_id = $1`,
      [principalId],
    );
    this.cache.set(principalId, { row, at: Date.now() });
    return row;
  }

  touch(principalId: string): void {
    if (Date.now() - (this.lastUsed.get(principalId) ?? 0) < LAST_USED_WRITE_INTERVAL_MS) return;
    this.lastUsed.set(principalId, Date.now());
    void this.db.query(`UPDATE service_principals SET last_used_at = now() WHERE principal_id = $1`, [principalId]).catch(() => undefined);
  }

  invalidate(): void {
    this.cache.clear();
  }
}
