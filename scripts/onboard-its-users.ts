import 'reflect-metadata';
import { parseArgs } from 'node:util';
import { DataSource } from 'typeorm';
import { loadEnv, loadEnvFiles } from '@config/configuration';
import { buildDataSourceOptions } from '@core/database/data-source-options';
import { chooseEmail, chooseName, parseAssignments } from '@common/utils/onboarding.util';

/**
 * Onboards ITS users into the Core Admin Control Panel (`miqaat_core`) and assigns their roles.
 *
 *   npm run onboard -- --list-roles
 *   npm run onboard -- --assign 10110101:role-platform-administrator
 *   npm run onboard -- --assign 10110107:role-rms-demo-admin,role-vms-demo-admin   # multi-role
 *   npm run onboard -- --assign 10110102:role-rms-demo-admin --dry-run
 *
 * Onboarding is the step that turns "can prove who they are" into "may use this panel". A user who
 * authenticates at core-authentication but has no `miqaat_core.users` row gets 403
 * USER_NOT_ONBOARDED from POST /v1/authorization/session; onboarded but roleless gets 403
 * NO_ROLE_ASSIGNED. This script is the deliberate act in between, and it touches ONLY miqaat_core -
 * never credentials, which live in core-authentication.
 *
 * Profile source, in order: an existing miqaat_core row, then the profile core-authentication has
 * already synced into public.users, then a synthesized placeholder. `miqaat_core.users.email` is
 * NOT NULL and UNIQUE while the upstream data frequently repeats or omits an address, so a
 * non-unique or missing email is replaced with `its-<itsId>@placeholder.invalid` - the .invalid TLD
 * is reserved by RFC 2606 and can never be routed to a real mailbox.
 *
 * Idempotent: re-running re-points the same user at the same roles without duplicating rows.
 */

async function main() {
  loadEnvFiles();
  const env = loadEnv();
  const { values } = parseArgs({
    options: {
      assign: { type: 'string', multiple: true, default: [] },
      'list-roles': { type: 'boolean', default: false },
      'dry-run': { type: 'boolean', default: false },
    },
  });

  const db = new DataSource(buildDataSourceOptions(env));
  await db.initialize();
  const runner = db.createQueryRunner();
  await runner.connect();
  const query = (sql: string, params?: unknown[]) => runner.query(sql, params);
  try {
    if (values['list-roles']) {
      const roles = (await query(
        `SELECT r.role_code, r.role_level, t.name AS tenant
           FROM miqaat_core.roles r
           LEFT JOIN miqaat_core.tenants t ON t.id = r.tenant_id
          ORDER BY r.role_level, r.role_code`,
      )) as { role_code: string; role_level: string; tenant: string | null }[];
      for (const r of roles) console.log(`${r.role_level.padEnd(20)} ${r.role_code.padEnd(36)} ${r.tenant ?? '(no tenant)'}`);
      return;
    }

    const assignments = parseAssignments(values.assign as string[]);
    if (!assignments.length) throw new Error('nothing to do: pass --assign <itsId>:<roleCode> (or --list-roles)');

    // Resolve every role up front: a typo must not leave half the batch onboarded.
    const wanted = [...new Set(assignments.flatMap((a) => a.roleCodes))];
    await runner.startTransaction();
    const found = (await query(
      `SELECT id, role_code, role_level FROM miqaat_core.roles WHERE role_code = ANY($1)`,
      [wanted],
    )) as { id: string; role_code: string; role_level: string }[];
    const roleByCode = new Map(found.map((r) => [r.role_code, r]));
    const missing = wanted.filter((c) => !roleByCode.has(c));
    if (missing.length) {
      throw new Error(`role code(s) not present in this database: ${missing.join(', ')} (run --list-roles to see what exists)`);
    }

    const summary = { onboarded: 0, alreadyPresent: 0, rolesAdded: 0, rolesAlreadyHeld: 0, emailsSynthesized: 0 };

    for (const a of assignments) {
      const existing = (await query(`SELECT id, email FROM miqaat_core.users WHERE its_id = $1`, [a.itsId])) as { id: string; email: string }[];

      let userId: string;
      if (existing[0]) {
        userId = existing[0].id;
        summary.alreadyPresent++;
      } else {
        // Prefer the profile core-authentication already pushed over inventing one.
        const synced = (await query(`SELECT name, email FROM public.users WHERE its_id = $1`, [a.itsId])) as
          | { name: string | null; email: string | null }[]
          | undefined;
        const name = chooseName(a.itsId, synced?.[0]?.name);

        const candidate = synced?.[0]?.email?.trim().toLowerCase() || null;
        const taken = candidate
          ? ((await query(`SELECT 1 FROM miqaat_core.users WHERE email = $1`, [candidate])) as unknown[]).length > 0
          : true;
        const { email, synthesized } = chooseEmail(a.itsId, candidate, taken);
        if (synthesized) summary.emailsSynthesized++;

        const inserted = (await query(
          // INVITED, not ACTIVE: ck_users_active_has_been_active requires an ACTIVE user to have
          // logged in at least once, and recordLogin() promotes INVITED -> ACTIVE on first sign-in.
          // Onboarding grants permission to sign in; it does not pretend the user already has.
          `INSERT INTO miqaat_core.users (its_id, name, email, status, has_been_active)
           VALUES ($1, $2, $3, 'INVITED', false)
           RETURNING id`,
          [a.itsId, name, email],
        )) as { id: string }[];
        userId = inserted[0].id;
        summary.onboarded++;
        if (values['dry-run']) {
          console.log(`would onboard ${a.itsId} as "${name}" <${email}>`);
        } else {
          console.log(`onboarded ${a.itsId} as "${name}" <${email}>`);
        }
      }

      for (const code of a.roleCodes) {
        const role = roleByCode.get(code)!;
        const held = (await query(`SELECT 1 FROM miqaat_core.user_roles WHERE user_id = $1 AND role_id = $2`, [userId, role.id])) as unknown[];
        if (held.length) {
          summary.rolesAlreadyHeld++;
          continue;
        }
        await query(`INSERT INTO miqaat_core.user_roles (user_id, role_id) VALUES ($1, $2)`, [userId, role.id]);
        summary.rolesAdded++;
        console.log(`  ${values['dry-run'] ? 'would assign' : 'assigned'} ${a.itsId} -> ${code} (${role.role_level})`);
      }
    }

    if (values['dry-run']) {
      await runner.rollbackTransaction();
      console.log('DRY RUN - rolled back, nothing was committed');
      console.log('would-be summary', summary);
      return;
    }
    await runner.commitTransaction();
    console.log('onboarding summary', summary);
  } catch (error) {
    if (runner.isTransactionActive) await runner.rollbackTransaction();
    throw error;
  } finally {
    await runner.release();
    await db.destroy();
  }
}

if (require.main === module) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
