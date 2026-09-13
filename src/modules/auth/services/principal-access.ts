import { DomainError } from '@common/errors/domain-error';
import { Principal } from '@shared/types/principal.types';

/** Client-scoped endpoints (authorization checks) are for service principals, restricted to their own client IDs. */
export function assertClientAllowed(principal: Principal | undefined, clientId: string): void {
  if (!principal) throw new DomainError('UNAUTHENTICATED', 'An Authorization: Bearer token is required', 401);
  if (principal.kind !== 'service') throw new DomainError('SERVICE_TOKEN_REQUIRED', 'This endpoint accepts service tokens only', 403);
  if (principal.allowedClientIds && !principal.allowedClientIds.includes(clientId)) {
    throw new DomainError('CLIENT_NOT_PERMITTED_FOR_PRINCIPAL', 'This service principal may not query the requested client', 403);
  }
}
