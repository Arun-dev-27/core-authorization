import { MigrationInterface, QueryRunner } from 'typeorm';

const S = 'miqaat_core';

/**
 * Miqaat Core Platform — Core Admin Control Panel data model (miqaat_core_db, Batch 1, file 3 of 3 continued).
 *
 * Adds user_sessions - the durable, system-of-record local session for the Core Admin Panel's ITS login
 * path, explicitly deferred in MiqaatCoreSchema1789600000000 ("Not implemented in this batch: login").
 * login_otp_codes (the Non-ITS email+OTP path) remains out of scope here.
 */
export class MiqaatCoreUserSessions1789700000000 implements MigrationInterface {
  name = 'MiqaatCoreUserSessions1789700000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE ${S}.user_sessions (
        id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id       uuid NOT NULL REFERENCES ${S}.users (id) ON DELETE CASCADE,
        role_id       uuid NOT NULL REFERENCES ${S}.roles (id) ON DELETE CASCADE,
        core_sid      text,
        aud           varchar(255),
        session_token text NOT NULL UNIQUE,
        ip_address    inet,
        user_agent    text,
        created_at    timestamptz NOT NULL DEFAULT now(),
        expires_at    timestamptz NOT NULL,
        revoked_at    timestamptz
      )`);
    await q.query(`CREATE INDEX ix_user_sessions_user_id ON ${S}.user_sessions (user_id)`);
    await q.query(`CREATE INDEX ix_user_sessions_session_token ON ${S}.user_sessions (session_token)`);
    await q.query(`CREATE INDEX ix_user_sessions_core_sid ON ${S}.user_sessions (core_sid)`);
    await q.query(`
      COMMENT ON TABLE ${S}.user_sessions IS
        'Opaque local session for the Core Admin Panel, scoped to one role for its lifetime. '
        'core_sid is the Core Federation Identity assertion sid this session was established under '
        '(join key for future back-channel logout); null for a non-federated session.'`);
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP TABLE IF EXISTS ${S}.user_sessions`);
  }
}
