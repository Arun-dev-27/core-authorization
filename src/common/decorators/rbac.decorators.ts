import { createParamDecorator, ExecutionContext, SetMetadata } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import type { PermissionAction } from '../constants/rbac.constants';

export const PERMISSION_KEY = 'miqaat:permission';
export const ACTIVE_SCOPE_KEY = 'miqaat:active-scope';
export const UNSCOPED_USER_KEY = 'miqaat:unscoped-user';
export const CORE_SCOPE_KEY = 'miqaat:core-scope';

export interface RequiredPermission {
  module: string;
  action: PermissionAction;
}

/**
 * Administrator route: the user's ACTIVE scope (role + scope from the token) must hold
 * <module>_<ACTION>. Service principals need the ADMIN scope (they act as CORE).
 */
export const RequirePermission = (module: string, action: PermissionAction) => SetMetadata(PERMISSION_KEY, { module, action } satisfies RequiredPermission);

/** User route that needs a selected workspace (active scope) but no specific permission, e.g. GET /me/permissions. */
export const RequireActiveScope = () => SetMetadata(ACTIVE_SCOPE_KEY, true);

/** User route usable before a workspace is selected, e.g. GET /me/assignments. */
export const AllowUnscopedUser = () => SetMetadata(UNSCOPED_USER_KEY, true);

/** Only a CORE active scope (Platform Administrator) or an ADMIN service principal may call this route. */
export const RequireCoreScope = () => SetMetadata(CORE_SCOPE_KEY, true);

/** Injects the resolved ActorContext (set by the global guard). */
export const Actor = createParamDecorator((_data: unknown, ctx: ExecutionContext) => ctx.switchToHttp().getRequest<FastifyRequest>().actor);
