/** PostgreSQL enum types that already exist in admin_db. Values mirror the database; never created from here. */
export const USER_STATUS = ['INVITED', 'ACTIVE', 'DISABLED'] as const;
export type UserStatus = (typeof USER_STATUS)[number];

export const TENANT_TYPE = ['BUSINESS_UNIT', 'UTILITY'] as const;
export type TenantType = (typeof TENANT_TYPE)[number];

export const TENANT_STATUS = ['ACTIVE', 'INACTIVE'] as const;
export type TenantStatus = (typeof TENANT_STATUS)[number];

export const ROLE_LEVEL = ['CORE_ADMIN', 'BUSINESS_UNIT_ADMIN', 'UTILITY_ADMIN'] as const;
export type RoleLevel = (typeof ROLE_LEVEL)[number];

export const ROLE_STATUS = ['ACTIVE', 'INACTIVE'] as const;
export type RoleStatus = (typeof ROLE_STATUS)[number];
