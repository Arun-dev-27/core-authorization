import type { ApiScope } from '@common/constants/api-scopes.constants';
import type { ScopeLevel } from '@common/constants/rbac.constants';

/** A calling service (Identity Federation, a BU backend, automation) authenticated by its own JWKS. */
export interface ServicePrincipal {
  kind: 'service';
  id: string;
  name: string;
  scopes: ApiScope[];
  /** When set, the principal may only query these client IDs (e.g. a BU backend). */
  allowedClientIds: string[] | null;
  tokenId: string;
}

/** Workspace selected via POST /select-scope, carried in the access token (never permissions). */
export interface ActiveScopeClaim {
  role_id: string;
  scope_type: ScopeLevel;
  scope_id: string | null;
}

/** A person authenticated by an Identity Federation access token. Rights come from Core RBAC for the active scope. */
export interface UserPrincipal {
  kind: 'user';
  id: string;
  itsId: string;
  sid?: string;
  activeScope?: ActiveScopeClaim;
  tokenId: string;
}

export type Principal = ServicePrincipal | UserPrincipal;

/** Who is acting, in which scope, with which permissions - resolved from the database on every request. */
export interface ActorContext {
  kind: 'service' | 'user';
  label: string;
  itsId: string | null;
  /** null = all tenants (ADMIN service principal). */
  tenantId: string | null;
  isCore: boolean;
  scopeType: ScopeLevel;
  scopeId: string | null;
  /** Business unit of the active scope (the BU itself, or the utility's parent BU). */
  scopeBuId: string | null;
  scopeName: string | null;
  roleId: string | null;
  roleName: string | null;
  permissions: ReadonlySet<string> | 'ALL';
}

declare module 'fastify' {
  interface FastifyRequest {
    principal?: Principal;
    actor?: ActorContext;
  }
}
