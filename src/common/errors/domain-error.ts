/**
 * Application error with a stable machine-readable code.
 * Messages must never contain secrets or credentials.
 */
export class DomainError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 400,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'DomainError';
  }

  static notFound(what: string, id: string): DomainError {
    return new DomainError(`${what.toUpperCase().replace(/\s+/g, '_')}_NOT_FOUND`, `${what} '${id}' was not found`, 404);
  }

  static conflict(code: string, message: string): DomainError {
    return new DomainError(code, message, 409);
  }
}
