import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource, EntityManager } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { UriType } from '@common/constants/client.constants';
import { DomainError } from '@common/errors/domain-error';
import { requestContext } from '@common/logging/request-context';
import { normalizeOrigin, normalizeRedirectUri } from '@common/utils/uri-policy';
import { AuditService } from '@core/audit/audit.service';
import { Queryable, queryMany, queryOne } from '@core/database/sql';
import { AuthzCacheService } from '@modules/authorization/services/authz-cache.service';
import { RbacService } from '@modules/rbac/services/rbac.service';
import { AuthenticationMode, ClientStatus, assertActivatable, assertTransition, requiresEmbedOrigins } from './client-lifecycle';
import type { AddCallbackInput, ClientQueryInput, CreateClientInput, UpdateClientInput } from './clients.types';

interface ClientRow {
  id: string;
  client_id: string;
  name: string;
  client_type: string;
  authentication_mode: AuthenticationMode;
  status: ClientStatus;
  initiate_login_uri: string | null;
  application_code: string;
  application_name: string;
  environment: string;
  business_unit: string | null;
  utility: string | null;
  created_at: Date;
  updated_at: Date;
}

/** Client configuration as consumed by Identity Federation (and shown to admins). */
export interface ClientConfig {
  client_id: string;
  name: string;
  application_code: string;
  application_name: string;
  business_unit: string | null;
  utility: string | null;
  environment: string;
  client_type: string;
  authentication_mode: AuthenticationMode;
  status: ClientStatus;
  allowed_embed_origins: string[];
  callback_uri: string | null;
  callback_uris: string[];
  back_channel_logout_uri: string | null;
  post_logout_redirect_uri: string | null;
  post_logout_redirect_uris: string[];
  initiate_login_uri: string | null;
  config_version: string;
}

const CLIENT_SELECT = `
  SELECT c.id, c.client_id, c.name, c.client_type, c.authentication_mode, c.status, c.initiate_login_uri,
         a.code AS application_code, a.name AS application_name, e.code AS environment,
         obu.name AS business_unit, aut.name AS utility, c.created_at, c.updated_at
    FROM clients c
    JOIN applications a ON a.application_id = c.application_id
    JOIN environments e ON e.id = c.environment_id
    LEFT JOIN utilities aut ON aut.utility_id = a.utility_id
    LEFT JOIN business_units obu ON obu.bu_id = COALESCE(a.bu_id, aut.bu_id)`;

@Injectable()
export class ClientsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly rbac: RbacService,
    private readonly audit: AuditService,
    private readonly cache: AuthzCacheService,
    private readonly config: AppConfig,
  ) {}

  private get allowInsecure(): boolean {
    return this.config.env.ALLOW_INSECURE_LOCALHOST_URIS;
  }

  async list(query: ClientQueryInput): Promise<ClientConfig[]> {
    const rows = await queryMany<ClientRow>(
      this.db,
      `${CLIENT_SELECT}
        WHERE ($1::varchar IS NULL OR a.code = $1) AND ($2::varchar IS NULL OR e.code = $2) AND ($3::varchar IS NULL OR c.status = $3)
        ORDER BY a.code, e.sort_order, c.client_id`,
      [query.application ?? null, query.environment ?? null, query.status ?? null],
    );
    return Promise.all(rows.map((row) => this.assemble(this.db, row)));
  }

  async getConfig(clientId: string, db: Queryable = this.db): Promise<ClientConfig> {
    const row = await queryOne<ClientRow>(db, `${CLIENT_SELECT} WHERE c.client_id = $1`, [clientId]);
    if (!row) throw DomainError.notFound('Client', clientId);
    return this.assemble(db, row);
  }

  async create(dto: CreateClientInput): Promise<ClientConfig> {
    const app = await this.rbac.applicationByCode(dto.application_code);
    const env = await this.rbac.environmentByCode(dto.environment_code);

    // Validate every URI before any write.
    const origins = [...new Set((dto.allowed_embed_origins ?? []).map((o) => normalizeOrigin(o, this.allowInsecure)))];
    const callbacks = [...new Set((dto.callback_uris ?? []).map((u) => normalizeRedirectUri(u, this.allowInsecure)))];
    const postLogout = [...new Set((dto.post_logout_redirect_uris ?? []).map((u) => normalizeRedirectUri(u, this.allowInsecure)))];
    const backChannel = dto.back_channel_logout_uri ? normalizeRedirectUri(dto.back_channel_logout_uri, this.allowInsecure) : null;
    const initiateLogin = dto.initiate_login_uri ? normalizeRedirectUri(dto.initiate_login_uri, this.allowInsecure) : null;

    const existing = await queryOne(this.db, `SELECT 1 FROM clients WHERE client_id = $1`, [dto.client_id]);
    if (existing) throw DomainError.conflict('CLIENT_ID_ALREADY_EXISTS', `Client ID '${dto.client_id}' is already registered`);

    const config = await this.db.transaction(async (tx) => {
      const client = await queryOne<{ id: string }>(
        tx,
        `INSERT INTO clients (client_id, application_id, environment_id, name, client_type, authentication_mode, status, initiate_login_uri)
         VALUES ($1, $2, $3, $4, $5, $6, 'PENDING', $7) RETURNING id`,
        [dto.client_id, app.id, env.id, dto.name ?? `${app.name} (${env.code})`, dto.client_type, dto.authentication_mode, initiateLogin],
      );
      const ref = client!.id;
      for (const origin of origins) await this.insertOrigin(tx, ref, origin);
      for (const [i, uri] of callbacks.entries()) await this.insertUri(tx, ref, uri, 'CALLBACK', i === 0);
      for (const [i, uri] of postLogout.entries()) await this.insertUri(tx, ref, uri, 'POST_LOGOUT_REDIRECT', i === 0);
      if (backChannel) await this.insertUri(tx, ref, backChannel, 'BACK_CHANNEL_LOGOUT', true);
      await tx.query(`INSERT INTO client_status_history (client_ref, from_status, to_status, reason, changed_by) VALUES ($1, NULL, 'PENDING', 'created', $2)`, [
        ref,
        this.actor(),
      ]);
      return this.getConfig(dto.client_id, tx);
    });

    await this.cache.invalidateAll();
    await this.audit.record({ eventType: 'CLIENT_CREATED', clientId: dto.client_id, resourceType: 'client', resourceId: dto.client_id });
    return config;
  }

  async update(clientId: string, dto: UpdateClientInput): Promise<ClientConfig> {
    let statusChange: { from: ClientStatus; to: ClientStatus } | null = null;

    const config = await this.db.transaction(async (tx) => {
      const current = await queryOne<{ id: string; status: ClientStatus; authentication_mode: AuthenticationMode }>(
        tx,
        `SELECT id, status, authentication_mode FROM clients WHERE client_id = $1 FOR UPDATE`,
        [clientId],
      );
      if (!current) throw DomainError.notFound('Client', clientId);
      if (current.status === 'RETIRED') throw new DomainError('CLIENT_RETIRED', 'Retired clients cannot be modified', 409);

      const mode = dto.authentication_mode ?? current.authentication_mode;
      const nextStatus = dto.status ?? current.status;
      assertTransition(current.status, nextStatus);

      if (dto.name !== undefined || dto.authentication_mode !== undefined || dto.initiate_login_uri !== undefined) {
        const initiate =
          dto.initiate_login_uri === undefined ? undefined : dto.initiate_login_uri === null ? null : normalizeRedirectUri(dto.initiate_login_uri, this.allowInsecure);
        await tx.query(
          `UPDATE clients SET
             name = COALESCE($2, name),
             authentication_mode = COALESCE($3, authentication_mode),
             initiate_login_uri = CASE WHEN $4::boolean THEN $5 ELSE initiate_login_uri END,
             updated_at = now()
           WHERE id = $1`,
          [current.id, dto.name ?? null, dto.authentication_mode ?? null, initiate !== undefined, initiate ?? null],
        );
      }

      if (dto.back_channel_logout_uri !== undefined) {
        await tx.query(`DELETE FROM client_redirect_uris WHERE client_ref = $1 AND uri_type = 'BACK_CHANNEL_LOGOUT'`, [current.id]);
        if (dto.back_channel_logout_uri !== null) {
          await this.insertUri(tx, current.id, normalizeRedirectUri(dto.back_channel_logout_uri, this.allowInsecure), 'BACK_CHANNEL_LOGOUT', true);
        }
        await this.touch(tx, current.id);
      }

      if (nextStatus === 'ACTIVE' || (current.status === 'ACTIVE' && dto.authentication_mode)) {
        const counts = await this.counts(tx, current.id);
        assertActivatable(mode, counts.origins, counts.callbacks);
      }

      if (nextStatus !== current.status) {
        await tx.query(`UPDATE clients SET status = $2, updated_at = now() WHERE id = $1`, [current.id, nextStatus]);
        await tx.query(
          `INSERT INTO client_status_history (client_ref, from_status, to_status, reason, changed_by) VALUES ($1, $2, $3, $4, $5)`,
          [current.id, current.status, nextStatus, dto.reason ?? null, this.actor()],
        );
        statusChange = { from: current.status, to: nextStatus };
      }
      return this.getConfig(clientId, tx);
    });

    await this.cache.invalidateAll();
    await this.audit.record({
      eventType: statusChange ? 'CLIENT_STATUS_CHANGED' : 'CLIENT_UPDATED',
      clientId,
      resourceType: 'client',
      resourceId: clientId,
      reason: dto.reason,
      metadata: statusChange ?? { fields: Object.keys(dto) },
    });
    return config;
  }

  async listOrigins(clientId: string) {
    const client = await this.requireClient(this.db, clientId);
    return queryMany(this.db, `SELECT origin, purpose, created_by, created_at FROM client_origins WHERE client_ref = $1 ORDER BY origin`, [client.id]);
  }

  async addOrigin(clientId: string, rawOrigin: string) {
    const origin = normalizeOrigin(rawOrigin, this.allowInsecure);
    await this.db.transaction(async (tx) => {
      const client = await this.requireClient(tx, clientId, true);
      await this.insertOrigin(tx, client.id, origin);
      await this.touch(tx, client.id);
    });
    await this.changed('CLIENT_ORIGIN_ADDED', clientId, { origin });
    return this.listOrigins(clientId);
  }

  async removeOrigin(clientId: string, rawOrigin: string) {
    const origin = normalizeOrigin(rawOrigin, this.allowInsecure);
    await this.db.transaction(async (tx) => {
      const client = await this.requireClient(tx, clientId, true);
      const registered = await queryOne(tx, `SELECT 1 FROM client_origins WHERE client_ref = $1 AND origin = $2`, [client.id, origin]);
      if (!registered) throw new DomainError('ORIGIN_NOT_REGISTERED', `Origin ${origin} is not registered for client ${clientId}`, 404);
      await tx.query(`DELETE FROM client_origins WHERE client_ref = $1 AND origin = $2`, [client.id, origin]);
      if (client.status === 'ACTIVE') {
        const counts = await this.counts(tx, client.id);
        assertActivatable(client.authentication_mode, counts.origins, counts.callbacks);
      }
      await this.touch(tx, client.id);
    });
    await this.changed('CLIENT_ORIGIN_REMOVED', clientId, { origin });
    return this.listOrigins(clientId);
  }

  async listCallbacks(clientId: string) {
    const client = await this.requireClient(this.db, clientId);
    return queryMany(
      this.db,
      `SELECT uri, uri_type, is_primary, created_by, created_at FROM client_redirect_uris WHERE client_ref = $1 ORDER BY uri_type, is_primary DESC, uri`,
      [client.id],
    );
  }

  async addCallback(clientId: string, dto: AddCallbackInput) {
    const type = dto.uri_type ?? 'CALLBACK';
    const uri = normalizeRedirectUri(dto.uri, this.allowInsecure);
    await this.db.transaction(async (tx) => {
      const client = await this.requireClient(tx, clientId, true);
      if (type === 'BACK_CHANNEL_LOGOUT') {
        await tx.query(`DELETE FROM client_redirect_uris WHERE client_ref = $1 AND uri_type = 'BACK_CHANNEL_LOGOUT'`, [client.id]);
      }
      const existingOfType = await queryOne<{ n: string }>(tx, `SELECT count(*) AS n FROM client_redirect_uris WHERE client_ref = $1 AND uri_type = $2`, [client.id, type]);
      const primary = dto.is_primary === true || Number(existingOfType?.n ?? 0) === 0;
      if (primary) {
        await tx.query(`UPDATE client_redirect_uris SET is_primary = false WHERE client_ref = $1 AND uri_type = $2`, [client.id, type]);
      }
      await this.insertUri(tx, client.id, uri, type, primary);
      await this.touch(tx, client.id);
    });
    await this.changed('CLIENT_URI_ADDED', clientId, { uri, uri_type: type });
    return this.listCallbacks(clientId);
  }

  async removeCallback(clientId: string, rawUri: string, type: UriType) {
    const uri = normalizeRedirectUri(rawUri, this.allowInsecure);
    await this.db.transaction(async (tx) => {
      const client = await this.requireClient(tx, clientId, true);
      const registered = await queryOne(tx, `SELECT 1 FROM client_redirect_uris WHERE client_ref = $1 AND uri = $2 AND uri_type = $3`, [client.id, uri, type]);
      if (!registered) throw new DomainError('URI_NOT_REGISTERED', `${type} ${uri} is not registered for client ${clientId}`, 404);
      await tx.query(`DELETE FROM client_redirect_uris WHERE client_ref = $1 AND uri = $2 AND uri_type = $3`, [client.id, uri, type]);
      if (client.status === 'ACTIVE') {
        const counts = await this.counts(tx, client.id);
        assertActivatable(client.authentication_mode, counts.origins, counts.callbacks);
      }
      await this.touch(tx, client.id);
    });
    await this.changed('CLIENT_URI_REMOVED', clientId, { uri, uri_type: type });
    return this.listCallbacks(clientId);
  }

  private async assemble(db: Queryable, row: ClientRow): Promise<ClientConfig> {
    const origins = await queryMany<{ origin: string }>(db, `SELECT origin FROM client_origins WHERE client_ref = $1 AND purpose = 'EMBED' ORDER BY created_at, origin`, [row.id]);
    const uris = await queryMany<{ uri: string; uri_type: UriType; is_primary: boolean }>(
      db,
      `SELECT uri, uri_type, is_primary FROM client_redirect_uris WHERE client_ref = $1 ORDER BY is_primary DESC, created_at, uri`,
      [row.id],
    );
    const ofType = (t: UriType) => uris.filter((u) => u.uri_type === t).map((u) => u.uri);
    const callbacks = ofType('CALLBACK');
    const postLogout = ofType('POST_LOGOUT_REDIRECT');
    return {
      client_id: row.client_id,
      name: row.name,
      application_code: row.application_code,
      application_name: row.application_name,
      business_unit: row.business_unit,
      utility: row.utility,
      environment: row.environment,
      client_type: row.client_type,
      authentication_mode: row.authentication_mode,
      status: row.status,
      allowed_embed_origins: origins.map((o) => o.origin),
      callback_uri: callbacks[0] ?? null,
      callback_uris: callbacks,
      back_channel_logout_uri: ofType('BACK_CHANNEL_LOGOUT')[0] ?? null,
      post_logout_redirect_uri: postLogout[0] ?? null,
      post_logout_redirect_uris: postLogout,
      initiate_login_uri: row.initiate_login_uri,
      config_version: new Date(row.updated_at).toISOString(),
    };
  }

  private async requireClient(db: Queryable, clientId: string, forUpdate = false) {
    const row = await queryOne<{ id: string; status: ClientStatus; authentication_mode: AuthenticationMode }>(
      db,
      `SELECT id, status, authentication_mode FROM clients WHERE client_id = $1 ${forUpdate ? 'FOR UPDATE' : ''}`,
      [clientId],
    );
    if (!row) throw DomainError.notFound('Client', clientId);
    if (forUpdate && row.status === 'RETIRED') throw new DomainError('CLIENT_RETIRED', 'Retired clients cannot be modified', 409);
    return row;
  }

  private async counts(db: Queryable, ref: string) {
    const row = await queryOne<{ origins: string; callbacks: string }>(
      db,
      `SELECT (SELECT count(*) FROM client_origins WHERE client_ref = $1) AS origins,
              (SELECT count(*) FROM client_redirect_uris WHERE client_ref = $1 AND uri_type = 'CALLBACK') AS callbacks`,
      [ref],
    );
    return { origins: Number(row?.origins ?? 0), callbacks: Number(row?.callbacks ?? 0) };
  }

  private insertOrigin(db: EntityManager, ref: string, origin: string) {
    return db.query(`INSERT INTO client_origins (client_ref, origin, created_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, [ref, origin, this.actor()]);
  }

  private insertUri(db: EntityManager, ref: string, uri: string, type: UriType, primary: boolean) {
    return db.query(
      `INSERT INTO client_redirect_uris (client_ref, uri, uri_type, is_primary, created_by) VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (client_ref, uri, uri_type) DO UPDATE SET is_primary = EXCLUDED.is_primary`,
      [ref, uri, type, primary, this.actor()],
    );
  }

  /** Bumps updated_at so config_version changes and caches in Identity Federation roll over. */
  private touch(db: EntityManager, ref: string) {
    return db.query(`UPDATE clients SET updated_at = now() WHERE id = $1`, [ref]);
  }

  private async changed(eventType: string, clientId: string, metadata: Record<string, unknown>) {
    await this.cache.invalidateAll();
    await this.audit.record({ eventType, clientId, resourceType: 'client', resourceId: clientId, metadata });
  }

  private actor(): string {
    return requestContext.getStore()?.actor ?? 'system';
  }

  static embedOriginsRequired = requiresEmbedOrigins;
}
