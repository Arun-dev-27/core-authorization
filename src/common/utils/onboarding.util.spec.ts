import { chooseEmail, chooseName, parseAssignments } from './onboarding.util';

describe('parseAssignments', () => {
  it('parses one user with one role', () => {
    expect(parseAssignments(['10110101:role-platform-administrator'])).toEqual([
      { itsId: '10110101', roleCodes: ['role-platform-administrator'] },
    ]);
  });

  it('parses a multi-role user, which is what triggers the role-selection screen', () => {
    expect(parseAssignments(['10110106:role-rms-demo-admin,role-vms-demo-admin,role-ams-demo-admin'])).toEqual([
      { itsId: '10110106', roleCodes: ['role-rms-demo-admin', 'role-vms-demo-admin', 'role-ams-demo-admin'] },
    ]);
  });

  it('merges repeated ITS IDs instead of overwriting them', () => {
    expect(parseAssignments(['10110106:role-a', '10110106:role-b'])).toEqual([
      { itsId: '10110106', roleCodes: ['role-a', 'role-b'] },
    ]);
  });

  it('collapses duplicate role codes', () => {
    expect(parseAssignments(['10110106:role-a,role-a', '10110106:role-a'])).toEqual([
      { itsId: '10110106', roleCodes: ['role-a'] },
    ]);
  });

  it('keeps distinct users separate and preserves their order', () => {
    const parsed = parseAssignments(['10110102:role-a', '10110101:role-b']);
    expect(parsed.map((p) => p.itsId)).toEqual(['10110102', '10110101']);
  });

  it('tolerates surrounding whitespace', () => {
    expect(parseAssignments([' 10110101 : role-a , role-b '])).toEqual([
      { itsId: '10110101', roleCodes: ['role-a', 'role-b'] },
    ]);
  });

  it.each([
    ['no separator', '10110101'],
    ['no roles', '10110101:'],
    ['roles but no id', ':role-a'],
    ['seven digits', '1011010:role-a'],
    ['nine digits', '101101011:role-a'],
    ['non-numeric id', 'NITS-0001:role-a'],
    ['empty', ''],
  ])('rejects %s', (_label, input) => {
    expect(() => parseAssignments([input])).toThrow();
  });

  it('rejects the whole batch when any entry is bad, rather than onboarding part of it', () => {
    expect(() => parseAssignments(['10110101:role-a', 'bogus:role-b'])).toThrow(/not an 8-digit ITS ID/);
  });
});

describe('chooseEmail', () => {
  it('uses a real address when it is present and free', () => {
    expect(chooseEmail('10110101', 'Person@Example.COM', false)).toEqual({ email: 'person@example.com', synthesized: false });
  });

  it('synthesizes when the address is already taken, because the column is UNIQUE', () => {
    expect(chooseEmail('10110102', 'shared@example.com', true)).toEqual({
      email: 'its-10110102@placeholder.invalid',
      synthesized: true,
    });
  });

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['blank', '   '],
  ])('synthesizes when the address is %s, because the column is NOT NULL', (_label, candidate) => {
    expect(chooseEmail('10110103', candidate as string | null | undefined, false)).toEqual({
      email: 'its-10110103@placeholder.invalid',
      synthesized: true,
    });
  });

  it('only ever synthesizes into .invalid, which cannot reach a real mailbox', () => {
    for (const its of ['10110101', '30416234']) {
      expect(chooseEmail(its, null, true).email.endsWith('@placeholder.invalid')).toBe(true);
    }
  });

  it('gives each ITS ID a distinct synthesized address', () => {
    const a = chooseEmail('10110101', null, true).email;
    const b = chooseEmail('10110102', null, true).email;
    expect(a).not.toBe(b);
  });
});

describe('chooseName', () => {
  it('prefers the upstream name', () => {
    expect(chooseName('10110101', '  Real Name  ')).toBe('Real Name');
  });

  it.each([
    ['null', null],
    ['blank', '   '],
  ])('falls back to the ITS ID when the name is %s (the column is NOT NULL)', (_label, candidate) => {
    expect(chooseName('10110101', candidate as string | null)).toBe('ITS 10110101');
  });
});
