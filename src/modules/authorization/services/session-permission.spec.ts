import { decideSessionPermission, type SessionPermissionState } from './session-permission';

const RMS = '11111111-1111-4111-8111-111111111111';
const AMS = '22222222-2222-4222-8222-222222222222';

const tenantAdmin = (over: Partial<SessionPermissionState> = {}): SessionPermissionState => ({
  userStatus: 'ACTIVE',
  roleStatus: 'ACTIVE',
  roleLevel: 'BUSINESS_UNIT_ADMIN',
  roleTenantId: RMS,
  tenantStatus: 'ACTIVE',
  permissions: { dashboard: { read: true }, usr: { read: true, update: true } },
  ...over,
});

describe('decideSessionPermission', () => {
  it('allows a granted module action inside the own tenant', () => {
    expect(decideSessionPermission(tenantAdmin(), { module: 'USR', action: 'UPDATE', tenantId: RMS })).toEqual({ allowed: true });
    expect(decideSessionPermission(tenantAdmin(), { module: 'usr', action: 'read' })).toEqual({ allowed: true });
  });

  it.each([
    ['action not granted', tenantAdmin(), { module: 'USR', action: 'CREATE' }, 'ACTION_NOT_GRANTED'],
    ['module not granted', tenantAdmin(), { module: 'BUM', action: 'READ' }, 'MODULE_NOT_GRANTED'],
    ['another tenant', tenantAdmin(), { module: 'USR', action: 'READ', tenantId: AMS }, 'TENANT_MISMATCH'],
    ['user disabled after login', tenantAdmin({ userStatus: 'DISABLED' }), { module: 'USR', action: 'READ' }, 'USER_NOT_ACTIVE'],
    ['role deactivated after login', tenantAdmin({ roleStatus: 'INACTIVE' }), { module: 'USR', action: 'READ' }, 'ROLE_NOT_ACTIVE'],
    ['tenant deactivated after login', tenantAdmin({ tenantStatus: 'INACTIVE' }), { module: 'USR', action: 'READ' }, 'TENANT_NOT_ACTIVE'],
  ] as const)('denies: %s', (_label, state, request, reason) => {
    expect(decideSessionPermission(state, request)).toEqual({ allowed: false, reason });
  });

  it('lets the platform-wide CORE_ADMIN role act on any tenant, still limited to its granted modules', () => {
    const core = tenantAdmin({ roleLevel: 'CORE_ADMIN', roleTenantId: null, tenantStatus: null, permissions: { bum: { read: true } } });
    expect(decideSessionPermission(core, { module: 'BUM', action: 'READ', tenantId: AMS })).toEqual({ allowed: true });
    expect(decideSessionPermission(core, { module: 'DCE', action: 'APPROVE', tenantId: AMS })).toEqual({ allowed: false, reason: 'MODULE_NOT_GRANTED' });
  });
});
