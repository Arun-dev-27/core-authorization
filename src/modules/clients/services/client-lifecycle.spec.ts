import { assertActivatable, assertTransition } from './client-lifecycle';

describe('client lifecycle', () => {
  it.each([
    ['PENDING', 'SECURITY_REVIEW'],
    ['SECURITY_REVIEW', 'ACTIVE'],
    ['ACTIVE', 'SUSPENDED'],
    ['SUSPENDED', 'ACTIVE'],
    ['SUSPENDED', 'RETIRED'],
  ] as const)('allows %s -> %s', (from, to) => {
    expect(() => assertTransition(from, to)).not.toThrow();
  });

  it.each([
    ['PENDING', 'ACTIVE'],
    ['RETIRED', 'ACTIVE'],
    ['ACTIVE', 'PENDING'],
    ['SUSPENDED', 'SECURITY_REVIEW'],
  ] as const)('rejects %s -> %s (no skipping security review, retired is terminal)', (from, to) => {
    expect(() => assertTransition(from, to)).toThrow('cannot change');
  });

  it('requires origins for embedded clients and callbacks for all', () => {
    expect(() => assertActivatable('EMBEDDED', 0, 1)).toThrow('embed origin');
    expect(() => assertActivatable('REDIRECT', 0, 0)).toThrow('callback');
    expect(() => assertActivatable('REDIRECT', 0, 1)).not.toThrow();
    expect(() => assertActivatable('EMBEDDED_OR_REDIRECT', 1, 1)).not.toThrow();
  });
});
