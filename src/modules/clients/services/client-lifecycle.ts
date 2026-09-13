import { DomainError } from '@common/errors/domain-error';

export const CLIENT_STATUSES = ['PENDING', 'SECURITY_REVIEW', 'ACTIVE', 'SUSPENDED', 'RETIRED'] as const;
export type ClientStatus = (typeof CLIENT_STATUSES)[number];

export const CLIENT_TYPES = ['WEB', 'SPA', 'MOBILE', 'SERVICE'] as const;
export const AUTHENTICATION_MODES = ['EMBEDDED', 'REDIRECT', 'EMBEDDED_OR_REDIRECT'] as const;
export type AuthenticationMode = (typeof AUTHENTICATION_MODES)[number];

/**
 * PENDING -> SECURITY_REVIEW -> ACTIVE -> SUSPENDED -> RETIRED
 * (review may bounce back to PENDING; a suspended client may be reinstated; RETIRED is terminal)
 */
const TRANSITIONS: Record<ClientStatus, readonly ClientStatus[]> = {
  PENDING: ['SECURITY_REVIEW', 'RETIRED'],
  SECURITY_REVIEW: ['ACTIVE', 'PENDING', 'RETIRED'],
  ACTIVE: ['SUSPENDED', 'RETIRED'],
  SUSPENDED: ['ACTIVE', 'RETIRED'],
  RETIRED: [],
};

export function assertTransition(from: ClientStatus, to: ClientStatus): void {
  if (from === to) return;
  if (!TRANSITIONS[from].includes(to)) {
    throw new DomainError('INVALID_CLIENT_STATUS_TRANSITION', `Client status cannot change from ${from} to ${to}`, 409, {
      allowed: TRANSITIONS[from],
    });
  }
}

export function requiresEmbedOrigins(mode: AuthenticationMode): boolean {
  return mode === 'EMBEDDED' || mode === 'EMBEDDED_OR_REDIRECT';
}

/** A client may only become ACTIVE once its security-relevant configuration is complete. */
export function assertActivatable(mode: AuthenticationMode, originCount: number, callbackCount: number): void {
  const problems: string[] = [];
  if (requiresEmbedOrigins(mode) && originCount === 0) problems.push('at least one allowed embed origin');
  if (callbackCount === 0) problems.push('at least one callback URI');
  if (problems.length > 0) {
    throw new DomainError('CLIENT_CONFIGURATION_INCOMPLETE', `Client requires ${problems.join(' and ')} before activation`, 409);
  }
}
