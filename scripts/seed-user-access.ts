/**
 * Assigns roles (role × scope) to users already synced from Identity Federation.
 *
 *  - the five demo users of the design deck, including a multi-workspace user (31267890)
 *  - the primary developer user 30337752 (Platform Administrator + application roles → workspace selection)
 *  - rotating application roles for every other synced user
 *
 *   npm run seed:access
 */
import 'reflect-metadata';
import Redis from 'ioredis';
import { loadEnv } from '@config/configuration';
import { ScopeLevel } from '@common/constants/rbac.constants';
import dataSource from '@core/database/data-source';

type Grant = [role: string, scopeType: ScopeLevel, scopeName: string | null];

const NAMED: Record<string, Grant[]> = {
  // Section 2 demo credentials
  '30416234': [['Platform Administrator', 'CORE', null]],
  '31189012': [['Business Unit Admin', 'BUSINESS_UNIT', 'RMS']],
  '31145678': [['BU Sub-Level Admin', 'BUSINESS_UNIT', 'RMS']],
  '31267890': [
    ['Utility Admin', 'UTILITY', 'Helpdesk'],
    ['Utility Admin', 'UTILITY', 'Zone Support'],
    ['Business Unit Admin', 'BUSINESS_UNIT', 'RMS'],
    ['Login Page Viewer', 'BUSINESS_UNIT', 'Core Services'], // can open the separate login page (:3100)
  ],
  '31278901': [['Utility Sub-Level Admin', 'UTILITY', 'Helpdesk']],
  // developer account used by the live federation tests
  '30337752': [
    ['Platform Administrator', 'CORE', null],
    ['RMS Registration Admin', 'BUSINESS_UNIT', 'RMS'],
    ['AMS User Admin', 'UTILITY', 'AMS'],
    ['VMS Viewer', 'BUSINESS_UNIT', 'VMS'],
    ['Mumin Member', 'BUSINESS_UNIT', 'Mumin Services'],
    ['Login Page User', 'BUSINESS_UNIT', 'Core Services'],
  ],
};

const PROFILES: Grant[][] = [
  [['RMS Viewer', 'BUSINESS_UNIT', 'RMS'], ['VMS Viewer', 'BUSINESS_UNIT', 'VMS'], ['Mumin Member', 'BUSINESS_UNIT', 'Mumin Services']],
  [['RMS Registration Operator', 'BUSINESS_UNIT', 'RMS'], ['AMS Viewer', 'UTILITY', 'AMS'], ['Mumin Member', 'BUSINESS_UNIT', 'Mumin Services']],
  [['VMS Events Admin', 'BUSINESS_UNIT', 'VMS'], ['Mumin Member', 'BUSINESS_UNIT', 'Mumin Services']],
];

async function main() {
  const env = loadEnv();
  await dataSource.initialize();
  const db = dataSource;
  const tenant = ((await db.query(`SELECT tenant_id FROM tenants WHERE name = $1`, [env.DEFAULT_TENANT_NAME])) as { tenant_id: string }[])[0];
  if (!tenant) throw new Error(`tenant '${env.DEFAULT_TENANT_NAME}' not found; run npm run seed first`);

  const users = (await db.query(`SELECT its_id FROM users WHERE tenant_id = $1 AND status = 'active' ORDER BY its_id`, [tenant.tenant_id])) as { its_id: string }[];
  const present = new Set(users.map((u) => u.its_id));

  async function scopeId(type: ScopeLevel, name: string | null): Promise<string | null> {
    if (type === 'CORE') return null;
    const rows = (type === 'BUSINESS_UNIT'
      ? await db.query(`SELECT bu_id AS id FROM business_units WHERE tenant_id = $1 AND name = $2`, [tenant.tenant_id, name])
      : await db.query(`SELECT u.utility_id AS id FROM utilities u JOIN business_units bu ON bu.bu_id = u.bu_id WHERE bu.tenant_id = $1 AND u.name = $2`, [
          tenant.tenant_id,
          name,
        ])) as { id: string }[];
    if (!rows[0]) throw new Error(`${type} '${name}' not found; run npm run seed first`);
    return rows[0].id;
  }

  let assigned = 0;
  let index = 0;
  const missing: string[] = [];
  for (const [itsId] of Object.entries(NAMED)) if (!present.has(itsId)) missing.push(itsId);

  for (const { its_id: itsId } of users) {
    const plan = NAMED[itsId] ?? (itsId.startsWith('NITS-') ? [['Mumin Member', 'BUSINESS_UNIT', 'Mumin Services'] as Grant] : PROFILES[index++ % PROFILES.length]);
    for (const [roleName, type, scopeName] of plan) {
      const role = ((await db.query(`SELECT role_id FROM roles WHERE tenant_id = $1 AND role_name = $2`, [tenant.tenant_id, roleName])) as { role_id: string }[])[0];
      if (!role) throw new Error(`role '${roleName}' not found; run npm run seed first`);
      const inserted = (await db.query(
        `INSERT INTO user_roles (its_id, role_id, scope_type, scope_id) VALUES ($1, $2, $3, $4)
         ON CONFLICT (its_id, role_id, (COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid))) DO NOTHING RETURNING its_id`,
        [itsId, role.role_id, type, await scopeId(type, scopeName)],
      )) as unknown[];
      assigned += inserted.length;
    }
  }

  const redis = new Redis(env.REDIS_URL);
  await redis.incr('authz:version');
  await redis.quit();

  const multi = (await db.query(`SELECT its_id, count(*)::int AS n FROM user_roles GROUP BY its_id HAVING count(*) > 1 ORDER BY its_id`)) as { its_id: string; n: number }[];
  console.log(`access seeded: ${users.length} users, ${assigned} new assignments; multi-workspace users: ${multi.map((m) => `${m.its_id}(${m.n})`).join(', ') || 'none'}`);
  if (missing.length) console.log(`not synced yet (run identity migrate:legacy / seed:dev-users, then re-run): ${missing.join(', ')}`);
  await dataSource.destroy();
}

main().catch(async (error: unknown) => {
  console.error('seed:access failed:', error instanceof Error ? error.message : error);
  await dataSource.destroy().catch(() => undefined);
  process.exit(1);
});
