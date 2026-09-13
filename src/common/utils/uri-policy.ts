import { DomainError } from '../errors/domain-error';

const LOCALHOST_NAMES = new Set(['localhost', '127.0.0.1', '[::1]']);

function parse(input: unknown, code: string, label: string): URL {
  if (typeof input !== 'string' || input.trim() === '') {
    throw new DomainError(code, `${label} is required`);
  }
  if (input.includes('*')) {
    throw new DomainError(code, `Wildcards are not allowed in ${label}`);
  }
  try {
    return new URL(input.trim());
  } catch {
    throw new DomainError(code, `${label} must be an absolute URL`);
  }
}

function assertScheme(url: URL, allowInsecureLocalhost: boolean, code: string, label: string): void {
  if (url.protocol === 'https:') return;
  if (url.protocol === 'http:' && allowInsecureLocalhost && LOCALHOST_NAMES.has(url.hostname)) return;
  throw new DomainError(code, `${label} must use https${allowInsecureLocalhost ? ' (http is allowed only for localhost)' : ''}`);
}

/**
 * Validates and canonicalises an embed origin. Only `scheme://host[:port]` is accepted:
 * no wildcard, path, query, fragment or credentials.
 */
export function normalizeOrigin(input: unknown, allowInsecureLocalhost: boolean): string {
  const url = parse(input, 'INVALID_ORIGIN', 'origin');
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new DomainError('INVALID_ORIGIN', 'origin must be scheme://host[:port] without path, query, fragment or credentials');
  }
  const raw = (input as string).trim().replace(/\/$/, '');
  if (raw.toLowerCase() !== url.origin.toLowerCase()) {
    throw new DomainError('INVALID_ORIGIN', 'origin must be scheme://host[:port]');
  }
  assertScheme(url, allowInsecureLocalhost, 'INVALID_ORIGIN', 'origin');
  return url.origin;
}

/** Validates and canonicalises a callback / logout URI for exact matching. */
export function normalizeRedirectUri(input: unknown, allowInsecureLocalhost: boolean): string {
  const url = parse(input, 'INVALID_REDIRECT_URI', 'uri');
  if (url.username || url.password || url.hash) {
    throw new DomainError('INVALID_REDIRECT_URI', 'uri must not contain credentials or a fragment');
  }
  assertScheme(url, allowInsecureLocalhost, 'INVALID_REDIRECT_URI', 'uri');
  return url.toString();
}
