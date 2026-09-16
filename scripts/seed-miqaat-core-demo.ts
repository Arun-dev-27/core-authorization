/**
 * Idempotent demo seed for the miqaat_core schema (Core Admin Control Panel):
 *  - three Business Unit tenants ("RMS Demo", "VMS Demo", "AMS Demo"), each with its own full-access
 *    BUSINESS_UNIT_ADMIN role
 *  - its_id 31189012: assigned to ALL THREE tenant admin roles - a deliberate multi-role persona for the
 *    "Where do you want to log in?" tenant-selection screen (POST /authorization/session ->
 *    selection_required -> POST /authorization/session/select). Every role is full-access, so the three
 *    cards differ only by tenant, not by permission shape - picking one and landing in the right tenant is
 *    the thing this demonstrates.
 *  - its_id 31267890: the platform-wide 'role-platform-administrator' CORE_ADMIN role already seeded
 *    by MiqaatCoreSchema1789600000000 - full access to every core-level module (single-role: exercises the
 *    plain, no-selection-screen login path)
 *  - its_id 31145678: 'role-rms-support-staff' - a NON-full-access sub-admin role for RMS Demo, granted
 *    only Ticket Management (read/update) and Audit Log (read) - exactly the kind of narrower role
 *    FR-6.1 describes a Business Unit Admin creating for their own staff, capped to a subset of what the
 *    tenant's admin role holds. Single-role too: demonstrates the sidebar shrinking without a selection screen.
 *
 * All ITS IDs are real core-authentication dev users (seed-dev-users.ts), so the local-session flow can be
 * exercised end to end with an actual login for any of them.
 *
 *   npm run seed:miqaat-core-demo
 */
import 'reflect-metadata';
import dataSource from '@core/database/data-source';
import { QueryRunner } from 'typeorm';

const MULTI_ROLE_ITS_ID = '31189012';
const MULTI_ROLE_NAME = 'Burhan (Demo)';
const TENANTS = [
  { name: 'RMS Demo', roleCode: 'role-rms-demo-admin', roleName: 'RMS Demo Admin' },
  { name: 'VMS Demo', roleCode: 'role-vms-demo-admin', roleName: 'VMS Demo Admin' },
  { name: 'AMS Demo', roleCode: 'role-ams-demo-admin', roleName: 'AMS Demo Admin' },
];
const CORE_ADMIN_ITS_ID = '31267890';
const CORE_ADMIN_NAME = 'Murtaza Saifuddin';
const LIMITED_ITS_ID = '31145678';
const LIMITED_NAME = 'BU Sub-Level Admin (Demo)';

async function ensureTenantAdminRole(tx: QueryRunner, tenantName: string, roleCode: string, roleName: string): Promise<string> {
  let tenant = await tx.query(`SELECT id FROM miqaat_core.tenants WHERE tenant_type = 'BUSINESS_UNIT' AND lower(trim(name)) = lower($1)`, [tenantName]);
  if (!tenant.length) {
    tenant = await tx.query(
      `INSERT INTO miqaat_core.tenants (tenant_type, name, description, onboarding_stage) VALUES ('BUSINESS_UNIT', $1, 'Seeded for the embed SDK demo', 'COMPLETED') RETURNING id`,
      [tenantName],
    );
    console.log(`created tenant ${tenantName}`);
  }
  const tenantId = tenant[0].id;

  let role = await tx.query(`SELECT id FROM miqaat_core.roles WHERE tenant_id = $1 AND role_level = 'BUSINESS_UNIT_ADMIN'`, [tenantId]);
  if (!role.length) {
    role = await tx.query(
      `INSERT INTO miqaat_core.roles (role_level, tenant_id, role_code, name, description, is_full_access)
       VALUES ('BUSINESS_UNIT_ADMIN', $1, $2, $3, $4, true) RETURNING id`,
      [tenantId, roleCode, roleName, `Seeded standard admin role for ${tenantName}.`],
    );
    const roleId = role[0].id;
    await tx.query(
      `INSERT INTO miqaat_core.role_permissions (role_id, module_action_id)
       SELECT $1, ma.id FROM miqaat_core.module_actions ma JOIN miqaat_core.modules m ON m.id = ma.module_id
        WHERE ma.applies_to_tenant AND m.applies_to_tenant`,
      [roleId],
    );
    console.log(`created role ${roleCode} with every tenant-level module action granted`);
  }
  return role[0].id;
}

async function main() {
  await dataSource.initialize();
  await dataSource.transaction(async (tx) => {
    let user = await tx.query(`SELECT id FROM miqaat_core.users WHERE its_id = $1`, [MULTI_ROLE_ITS_ID]);
    if (!user.length) {
      user = await tx.query(
        `INSERT INTO miqaat_core.users (its_id, name, email, status, has_been_active)
         VALUES ($1, $2, 'burhan.demo@example.com', 'ACTIVE', true) RETURNING id`,
        [MULTI_ROLE_ITS_ID, MULTI_ROLE_NAME],
      );
      console.log(`created user its_id=${MULTI_ROLE_ITS_ID}`);
    }
    const userId = user[0].id;

    for (const tenant of TENANTS) {
      const roleId = await ensureTenantAdminRole(tx, tenant.name, tenant.roleCode, tenant.roleName);
      const existingAssignment = await tx.query(`SELECT id FROM miqaat_core.user_roles WHERE user_id = $1 AND role_id = $2`, [userId, roleId]);
      if (!existingAssignment.length) {
        await tx.query(`INSERT INTO miqaat_core.user_roles (user_id, role_id) VALUES ($1, $2)`, [userId, roleId]);
        console.log(`assigned its_id=${MULTI_ROLE_ITS_ID} to ${tenant.roleCode} at tenant ${tenant.name}`);
      }
    }

    const coreRole = await tx.query(`SELECT id FROM miqaat_core.roles WHERE role_code = 'role-platform-administrator'`);
    if (!coreRole.length) throw new Error("role-platform-administrator not found - has MiqaatCoreSchema1789600000000 run?");
    const coreRoleId = coreRole[0].id;

    let coreUser = await tx.query(`SELECT id FROM miqaat_core.users WHERE its_id = $1`, [CORE_ADMIN_ITS_ID]);
    if (!coreUser.length) {
      coreUser = await tx.query(
        `INSERT INTO miqaat_core.users (its_id, name, email, status, has_been_active)
         VALUES ($1, $2, $3, 'ACTIVE', true) RETURNING id`,
        [CORE_ADMIN_ITS_ID, CORE_ADMIN_NAME, 'murtaza.demo@example.com'],
      );
      console.log(`created user its_id=${CORE_ADMIN_ITS_ID}`);
    }
    const coreUserId = coreUser[0].id;

    const existingCoreAssignment = await tx.query(`SELECT id FROM miqaat_core.user_roles WHERE user_id = $1 AND role_id = $2`, [coreUserId, coreRoleId]);
    if (!existingCoreAssignment.length) {
      await tx.query(`INSERT INTO miqaat_core.user_roles (user_id, role_id) VALUES ($1, $2)`, [coreUserId, coreRoleId]);
      console.log(`assigned its_id=${CORE_ADMIN_ITS_ID} to role-platform-administrator`);
    }

    const rmsTenant = await tx.query(`SELECT id FROM miqaat_core.tenants WHERE tenant_type = 'BUSINESS_UNIT' AND lower(trim(name)) = lower($1)`, ['RMS Demo']);
    const rmsTenantId = rmsTenant[0].id;

    let limitedRole = await tx.query(`SELECT id FROM miqaat_core.roles WHERE role_code = 'role-rms-support-staff'`);
    if (!limitedRole.length) {
      limitedRole = await tx.query(
        `INSERT INTO miqaat_core.roles (role_level, tenant_id, role_code, name, description, is_full_access)
         VALUES ('BUSINESS_UNIT_ADMIN', $1, 'role-rms-support-staff', 'RMS Support Staff', 'Seeded limited sub-admin role: Ticket Management + Audit Log only.', false) RETURNING id`,
        [rmsTenantId],
      );
      const limitedRoleId = limitedRole[0].id;
      await tx.query(
        `INSERT INTO miqaat_core.role_permissions (role_id, module_action_id)
         SELECT $1, ma.id
           FROM miqaat_core.module_actions ma
           JOIN miqaat_core.modules m ON m.id = ma.module_id
           JOIN miqaat_core.permission_actions a ON a.id = ma.action_id
          WHERE ma.applies_to_tenant AND m.applies_to_tenant
            AND ((m.code = 'TKT' AND a.code IN ('READ', 'UPDATE')) OR (m.code = 'AUD' AND a.code = 'READ'))`,
        [limitedRoleId],
      );
      console.log('created role role-rms-support-staff with only Ticket Management (read/update) + Audit Log (read) granted');
    }
    const limitedRoleId = limitedRole[0].id;

    let limitedUser = await tx.query(`SELECT id FROM miqaat_core.users WHERE its_id = $1`, [LIMITED_ITS_ID]);
    if (!limitedUser.length) {
      limitedUser = await tx.query(
        `INSERT INTO miqaat_core.users (its_id, name, email, status, has_been_active)
         VALUES ($1, $2, $3, 'ACTIVE', true) RETURNING id`,
        [LIMITED_ITS_ID, LIMITED_NAME, 'bu-sub-admin.demo@example.com'],
      );
      console.log(`created user its_id=${LIMITED_ITS_ID}`);
    }
    const limitedUserId = limitedUser[0].id;

    const existingLimitedAssignment = await tx.query(`SELECT id FROM miqaat_core.user_roles WHERE user_id = $1 AND role_id = $2`, [limitedUserId, limitedRoleId]);
    if (!existingLimitedAssignment.length) {
      await tx.query(`INSERT INTO miqaat_core.user_roles (user_id, role_id) VALUES ($1, $2)`, [limitedUserId, limitedRoleId]);
      console.log(`assigned its_id=${LIMITED_ITS_ID} to role-rms-support-staff at tenant RMS Demo`);
    }
  });
  await dataSource.destroy();
  console.log('miqaat_core demo seed complete');
}

main().catch(async (error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  await dataSource.destroy().catch(() => undefined);
  process.exit(1);
});
