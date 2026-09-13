import { CanActivate, ExecutionContext, Injectable, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { FastifyRequest } from 'fastify';
import { ApiScope } from '@common/constants/api-scopes.constants';
import { permissionCode } from '@common/constants/rbac.constants';
import { PUBLIC_KEY } from '@common/decorators/public.decorator';
import { ACTIVE_SCOPE_KEY, CORE_SCOPE_KEY, PERMISSION_KEY, RequiredPermission, UNSCOPED_USER_KEY } from '@common/decorators/rbac.decorators';
import { SCOPES_KEY } from '@common/decorators/require-scopes.decorator';
import { DomainError } from '@common/errors/domain-error';
import { requestContext } from '@common/logging/request-context';
import { AuditService } from '@core/audit/audit.service';
import { RbacService } from '@modules/rbac/services/rbac.service';
import { ActorContext, Principal } from '@shared/types/principal.types';
import { InvalidTokenError, TokenVerifier } from '../services/token-verifier.service';

/**
 * Global guard. Deny by default.
 *
 *  @Public()              no authentication
 *  @RequireScopes(...)    service principals holding one of the scopes (ADMIN satisfies all)
 *  @RequirePermission()   administrator user with an active workspace holding <MODULE>_<ACTION>
 *                         (or an ADMIN service principal, which acts as CORE)
 *  @RequireActiveScope()  user with a selected workspace
 *  @AllowUnscopedUser()   any authenticated user, before selecting a workspace
 *  @RequireCoreScope()    additionally requires a CORE workspace
 *
 * Permissions are always read from the database for the token's active scope - never from the token.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly verifier: TokenVerifier,
    private readonly rbac: RbacService,
    private readonly audit: AuditService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, targets)) return true;

    const request = context.switchToHttp().getRequest<FastifyRequest>();
    let principal: Principal;
    try {
      principal = await this.verifier.verify(request.headers.authorization);
    } catch (error) {
      if (error instanceof InvalidTokenError) this.logger.warn({ msg: 'bearer token rejected', reason: error.reason, path: request.url.split('?')[0] });
      throw error;
    }
    // Label the actor before any authorization decision so denial audit records name the caller.
    const store = requestContext.getStore();
    if (store) store.actor = principal.kind === 'service' ? `svc:${principal.id}` : `user:${principal.itsId}`;

    const permission =this.reflector.getAllAndOverride<RequiredPermission>(PERMISSION_KEY, targets);
    const scopes = this.reflector.getAllAndOverride<ApiScope[]>(SCOPES_KEY, targets) ?? [];
    const activeScopeOnly = this.reflector.getAllAndOverride<boolean>(ACTIVE_SCOPE_KEY, targets) ?? false;
    const unscoped = this.reflector.getAllAndOverride<boolean>(UNSCOPED_USER_KEY, targets) ?? false;
    const coreOnly = this.reflector.getAllAndOverride<boolean>(CORE_SCOPE_KEY, targets) ?? false;
    if (!permission && scopes.length === 0 && !activeScopeOnly && !unscoped) throw new DomainError('FORBIDDEN', 'Endpoint is not accessible', 403);

    let actor: ActorContext | undefined;
    if (principal.kind === 'service') {
      if (activeScopeOnly || unscoped) throw new DomainError('USER_TOKEN_REQUIRED', 'This endpoint accepts user access tokens only', 403);
      const required: ApiScope[] = permission ? [...scopes, 'ADMIN'] : scopes;
      const allowed = principal.scopes.includes('ADMIN') || required.some((scope) => principal.scopes.includes(scope));
      if (!allowed) throw new DomainError('FORBIDDEN_SCOPE', 'The service principal does not have the required scope', 403);
      if (principal.scopes.includes('ADMIN')) actor = await this.rbac.actorFor(principal);
    } else if (!unscoped) {
      if (!permission && !activeScopeOnly) throw new DomainError('SERVICE_TOKEN_REQUIRED', 'This endpoint accepts service tokens only', 403);
      actor = await this.rbac.actorFor(principal);
      if (permission) {
        const code = permissionCode(permission.module, permission.action);
        if (!this.rbac.hasPermission(actor, code)) {
          await this.audit.record({
            eventType: 'ADMIN_ACCESS_DENIED',
            itsId: principal.itsId,
            resourceType: 'permission',
            resourceId: code,
            decision: 'DENY',
            reason: 'PERMISSION_DENIED',
            metadata: { method: request.method, path: request.url.split('?')[0], role: actor.roleName, scope_type: actor.scopeType, scope_id: actor.scopeId },
          });
          throw new DomainError('PERMISSION_DENIED', 'Your workspace does not have permission to perform this action', 403, { permission: code });
        }
      }
    }
    if (coreOnly && !actor?.isCore) throw new DomainError('CORE_SCOPE_REQUIRED', 'This action requires a Platform Administrator (CORE) workspace', 403);

    request.principal = principal;
    request.actor = actor;
    return true;
  }
}
