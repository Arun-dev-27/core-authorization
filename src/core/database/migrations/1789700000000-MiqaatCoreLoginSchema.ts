import { MigrationInterface, QueryRunner } from 'typeorm';

const S = 'miqaat_core';

/**
 * Miqaat Core Platform — Core Admin Control Panel, completion of Batch 1 file 3
 * (03-users-and-auth.dbml): local sessions, Non-ITS members and their one-time-code login.
 *
 *   users.its_id      becomes nullable — NULL is a Non-ITS member (email + one-time code)
 *   user_sessions     the durable record of one signed-in session, acting as exactly one role
 *   login_otp_codes   hashed one-time codes for the Non-ITS email login path
 *
 * Two login paths, deliberately different in how much this database owns:
 *  - ITS ID + password is verified entirely by the Core Federation Identity Service (RS256
 *    assertion verified through its JWKS). This database only records the outcome, via
 *    user_sessions.core_sid (the assertion's `sid`) and user_sessions.aud (its `client_id`).
 *    No password, assertion or token is ever stored here.
 *  - Non-ITS email + one-time code is fully local: login_otp_codes holds only a hash, and the
 *    resulting session has core_sid = NULL.
 *
 * Runtime state that deliberately stays out of PostgreSQL: the per-request session cache,
 * the JTI replay store and the JWKS cache all live in Redis.
 */
export class MiqaatCoreLoginSchema1789700000000 implements MigrationInterface {
  name = 'MiqaatCoreLoginSchema1789700000000';

  public async up(q: QueryRunner): Promise<void> {
    // ------------------------------------------------------------------ Non-ITS members
    // A CHECK passes when its expression is NULL, so the 8-digit rule still applies to ITS
    // members only, and UNIQUE keeps allowing many NULLs (one per Non-ITS member).
    await q.query(`ALTER TABLE ${S}.users ALTER COLUMN its_id DROP NOT NULL`);
    await q.query(
      `COMMENT ON COLUMN ${S}.users.its_id IS 'NULL for a Non-ITS member (email + one-time code login); exactly 8 digits for an ITS member (FR-1.1).'`,
    );

    // ------------------------------------------------------------------ local sessions
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
        revoked_at    timestamptz,
        CONSTRAINT ck_user_sessions_expires_after_created CHECK (expires_at > created_at),
        CONSTRAINT ck_user_sessions_federation_pair CHECK ((core_sid IS NULL) = (aud IS NULL))
      )`);
    await q.query(`CREATE INDEX ix_user_sessions_user_id ON ${S}.user_sessions (user_id)`);
    await q.query(`CREATE INDEX ix_user_sessions_core_sid ON ${S}.user_sessions (core_sid) WHERE core_sid IS NOT NULL`);
    await q.query(`CREATE INDEX ix_user_sessions_live ON ${S}.user_sessions (user_id, expires_at) WHERE revoked_at IS NULL`);

    await q.query(`
      COMMENT ON TABLE ${S}.user_sessions IS
        'One signed-in session, acting as exactly one role for its whole lifetime (FR-1.3: switching roles requires signing in again). Live = revoked_at IS NULL AND expires_at > now().'`);
    await q.query(
      `COMMENT ON COLUMN ${S}.user_sessions.role_id IS 'The role chosen at Multi-Role Profile Selection. Never taken from the federation assertion, which carries identity only.'`,
    );
    await q.query(
      `COMMENT ON COLUMN ${S}.user_sessions.core_sid IS 'Federation session id (assertion sid) this session was established under; NULL for a local Non-ITS session. Not unique: one federation session may back several local sessions (e.g. two tabs). Back-channel logout: UPDATE ... SET revoked_at = now() WHERE core_sid = :sid AND revoked_at IS NULL.'`,
    );
    await q.query(
      `COMMENT ON COLUMN ${S}.user_sessions.aud IS 'Federation client_id the assertion was issued for (e.g. core-admin-web-prod); NULL for a local Non-ITS session, like core_sid.'`,
    );
    await q.query(
      `COMMENT ON COLUMN ${S}.user_sessions.session_token IS 'Opaque local session identifier sent as an HttpOnly, Secure cookie. Never the federation assertion itself, which is one-time and is never persisted.'`,
    );

    // ------------------------------------------------------------------ Non-ITS one-time codes
    await q.query(`
      CREATE TABLE ${S}.login_otp_codes (
        id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id       uuid NOT NULL REFERENCES ${S}.users (id) ON DELETE CASCADE,
        code_hash     text NOT NULL,
        expires_at    timestamptz NOT NULL,
        consumed_at   timestamptz,
        attempt_count integer NOT NULL DEFAULT 0,
        created_at    timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT ck_login_otp_codes_attempts_non_negative CHECK (attempt_count >= 0),
        CONSTRAINT ck_login_otp_codes_expires_after_created CHECK (expires_at > created_at)
      )`);
    await q.query(`CREATE INDEX ix_login_otp_codes_user_id ON ${S}.login_otp_codes (user_id, created_at DESC)`);
    await q.query(`CREATE INDEX ix_login_otp_codes_pending ON ${S}.login_otp_codes (user_id) WHERE consumed_at IS NULL`);

    await q.query(`
      COMMENT ON TABLE ${S}.login_otp_codes IS
        'Non-ITS email + one-time code sign-in (FR-1.2) only. ITS members never appear here: their credentials are verified by the Core Federation Identity Service.'`);
    await q.query(
      `COMMENT ON COLUMN ${S}.login_otp_codes.code_hash IS 'Hash of the emailed one-time code. The plaintext code is never stored.'`,
    );
    await q.query(
      `COMMENT ON COLUMN ${S}.login_otp_codes.attempt_count IS 'Wrong-code attempts against this code; the application decides the lockout and resend thresholds.'`,
    );
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP TABLE IF EXISTS ${S}.login_otp_codes`);
    await q.query(`DROP TABLE IF EXISTS ${S}.user_sessions`);
    // Restoring NOT NULL would silently break Non-ITS members: fail loudly instead of deleting them.
    await q.query(`
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM ${S}.users WHERE its_id IS NULL) THEN
          RAISE EXCEPTION 'cannot revert: Non-ITS members exist (users.its_id IS NULL); remove or migrate them first';
        END IF;
      END $$`);
    await q.query(`ALTER TABLE ${S}.users ALTER COLUMN its_id SET NOT NULL`);
    await q.query(`COMMENT ON COLUMN ${S}.users.its_id IS NULL`);
  }
}
