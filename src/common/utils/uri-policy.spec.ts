import { normalizeOrigin, normalizeRedirectUri } from './uri-policy';

describe('uri-policy', () => {
  describe('normalizeOrigin', () => {
    it('accepts an exact https origin and canonicalises case/trailing slash', () => {
      expect(normalizeOrigin('https://RMS.example.com/', false)).toBe('https://rms.example.com');
      expect(normalizeOrigin('https://rms.example.com:8443', false)).toBe('https://rms.example.com:8443');
    });

    it.each([
      ['*'],
      ['https://*.example.com'],
      ['https://rms.example.com/path'],
      ['https://rms.example.com?x=1'],
      ['https://rms.example.com#frag'],
      ['https://user:pw@rms.example.com'],
      ['rms.example.com'],
      ['javascript:alert(1)'],
      ['null'],
      [''],
    ])('rejects %s', (value) => {
      expect(() => normalizeOrigin(value, true)).toThrow();
    });

    it('rejects http unless localhost is explicitly allowed', () => {
      expect(() => normalizeOrigin('http://rms.example.com', true)).toThrow();
      expect(() => normalizeOrigin('http://localhost:4001', false)).toThrow();
      expect(normalizeOrigin('http://localhost:4001', true)).toBe('http://localhost:4001');
    });
  });

  describe('normalizeRedirectUri', () => {
    it('accepts https callback with path', () => {
      expect(normalizeRedirectUri('https://rms.example.com/auth/core/callback', false)).toBe(
        'https://rms.example.com/auth/core/callback',
      );
    });

    it.each([['https://rms.example.com/cb#x'], ['https://*.example.com/cb'], ['http://evil.example.com/cb'], ['/relative']])(
      'rejects %s',
      (value) => {
        expect(() => normalizeRedirectUri(value, true)).toThrow();
      },
    );
  });
});
