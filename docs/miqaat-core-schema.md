# `miqaat_core` schema (Core Admin Control Panel data model, Batch 1)

Implementation of the `miqaat_core_db` DBML (files 1–3) as PostgreSQL schema `miqaat_core` inside the Authorization DB.
Migration: `src/core/database/migrations/1789600000000-MiqaatCoreSchema.ts`. Tests: `test/miqaat-core-schema.e2e-spec.ts`.

It is **additive**: the existing `public` tables used by the Authorization service (`tenants`, `business_units`, `utilities`,
`roles`, `modules`, `permissions`, `users`, `user_roles`, …) and all service code are unchanged. No API reads or writes
`miqaat_core` yet.

```bash
npm run migration:run      # creates the schema
npm run migration:revert   # drops it again (DROP SCHEMA miqaat_core CASCADE)
```

## Scope

| DBML file | Tables implemented | Not implemented |
|---|---|---|
| 1. Tenants and domains | `tenants`, `tenant_domains`, `tenant_domain_credentials`, `tenant_core_credentials`, `platform_settings`, `tenant_rate_limits` | — |
| 2. Modules, roles, permissions | `modules`, `permission_actions`, `module_actions`, `roles`, `role_permissions` | — |
| 3. Users and auth | `users`, `user_roles` | `user_sessions`, `login_otp_codes` (login is out of scope) |

**Non-ITS members are out of scope:** `users.its_id` is `NOT NULL` and must be exactly 8 digits.

## Enums

Real PostgreSQL enum types, declared in flow order (so `onboarding_stage >= 'VERIFY_CONNECTION'` works):
`tenant_type`, `tenant_status`, `auth_header_type`, `config_duration_unit`, `rate_limit_quota_period`, `onboarding_stage`,
`role_level`, `role_status`, `user_status`.

## Rules enforced in the database

| Rule (DBML note) | How |
|---|---|
| Tenant name unique per type, case-insensitive, trimmed | `uq_tenants_type_name_ci` on `(tenant_type, lower(trim(name)))`; blank names rejected |
| Exactly one default domain per tenant | partial unique index `uq_tenant_domains_one_default … WHERE is_default` |
| `custom_header_name` required when `auth_header_type = CUSTOM` | `ck_tenant_domains_custom_header` |
| One reciprocal credential per domain; one Core credential set and one rate-limit row per tenant | `UNIQUE` foreign keys |
| `platform_settings` is a singleton | `id` defaults to 1, `CHECK (id = 1)` |
| Quota values required when quota is enabled | `ck_platform_settings_core_quota`, `ck_tenant_rate_limits_quota` |
| SLA ceiling 28 s; default ≤ maximum | `ck_platform_settings_sla`, `ck_tenant_rate_limits_sla` (tenant ≤ platform value stays an application check) |
| `tenant_id IS NULL` ⇔ `role_level = CORE_ADMIN` | `ck_roles_tenant_scope` |
| One full-access role platform-wide at Core level, one per tenant | `uq_roles_one_core_full_access`, `uq_roles_one_full_access_per_tenant` |
| `created_by_core_admin` derived, never app-set | `GENERATED ALWAYS AS (role_level = 'CORE_ADMIN' OR is_full_access) STORED` |
| `role_code` stable slug, unique platform-wide | `UNIQUE` + format `role-<slug>` |
| A grant must reference an offered (module, action) pair | `role_permissions.module_action_id` → `module_actions` (`RESTRICT`) |
| One role per user per tenant; one Core Admin role per user | partial unique indexes `uq_user_roles_one_role_per_tenant`, `uq_user_roles_one_core_admin_role` |
| `user_roles.tenant_id` / `role_level` are copies of the role's values | trigger `trg_user_roles_copy_role` sets them on insert and when `role_id` changes |
| `status = ACTIVE` implies `has_been_active` | `ck_users_active_has_been_active` |
| `updated_at` reflects the last change | `BEFORE UPDATE` triggers on every table that has the column |

Two integrity checks the notes imply, added as triggers:

- **Role level matches tenant type** (`trg_roles_check_tenant_type`): a `BUSINESS_UNIT_ADMIN` role belongs to a `BUSINESS_UNIT`
  tenant, a `UTILITY_ADMIN` role to a `UTILITY` tenant.
- **Checkbox offered for the role's level** (`trg_role_permissions_check_level`): the module and the module action must both
  apply to the role's level, so APPROVE on DCE can never be granted to a Core Admin-level role and BUM/UTM/MUM never to a tenant role.

Left to the application, as the DBML notes say: "at least one domain" once a tenant manages its Configuration, capping a
sub-admin's matrix to the creating admin's own grants, the Admin Creation Cap count, slug collision handling for `role_code`,
IANA timezone validation, and encrypting secret columns before they are written.

## Seed data (created by the migration)

- `permission_actions`: `CREATE`, `READ`, `UPDATE`, `APPROVE`.
- `modules`: `ROLE`, `USR`, `BUM`, `UTM`, `CFG`, `MUM`, `DCE`, `MON`, `AUD`, `TKT`. `BUM`, `UTM`, `MUM` are Core-only; the rest apply to every level.
- `module_actions` (30 rows): every module × CREATE/READ/UPDATE except `CFG × CREATE`, plus `DCE × APPROVE` for tenant-level roles only.
- `roles`: `role-platform-administrator` (CORE_ADMIN, full access, locked) with all 29 Core-level checkboxes.

`platform_settings` is not seeded: the event bus name/ARN, rate limits and SLA timeouts have no defaults in the model.
