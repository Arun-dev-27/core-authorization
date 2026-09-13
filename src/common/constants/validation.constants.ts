export const ITS_ID = /^[A-Za-z0-9._-]{1,64}$/;
export const CLIENT_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
export const APPLICATION_CODE = /^[a-z0-9][a-z0-9-]{1,63}$/;
/** Kept for client DTOs: application codes are lowercase. */
export const CODE_LOWER = APPLICATION_CODE;
export const ENVIRONMENT_CODE = /^[A-Z0-9_]{2,16}$/;
/** Core RBAC module code, e.g. DASHBOARD, ROLE_MGMT, RMS_REGISTRATION. */
export const MODULE_CODE = /^[A-Z][A-Z0-9_]{1,63}$/;
/** <MODULE_CODE>_<ACTION>, e.g. ROLE_MGMT_CREATE. */
export const PERMISSION_CODE = /^[A-Z][A-Z0-9_]{1,127}$/;
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
