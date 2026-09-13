export const API_SCOPES = ['ADMIN', 'FEDERATION', 'AUTHZ_CHECK'] as const;
export type ApiScope = (typeof API_SCOPES)[number];
