import { AuthorizationEngine, EffectiveAccess, GrantRow } from './authorization.engine';

const BU = '0f8e7d6c-5b4a-4938-8271-605f4e3d2c1b';
const grant = (role: string, module: string, code: string, scopeType: GrantRow['scope_type'] = 'BUSINESS_UNIT'): GrantRow => ({
  role_id: `role-${role}`,
  role_name: role,
  scope_type: scopeType,
  scope_id: scopeType === 'CORE' ? null : BU,
  module_code: module,
  module_name: module,
  permission_code: code,
});

const granted = (): EffectiveAccess => ({
  its_id: '30337752',
  client_id: 'rms-web-prod',
  access: 'GRANTED',
  roles: [],
  modules: [{ code: 'RMS_REGISTRATION', name: 'Registration', permissions: ['RMS_REGISTRATION_CREATE', 'RMS_REGISTRATION_VIEW'] }],
  permissions: ['RMS_REGISTRATION_CREATE', 'RMS_REGISTRATION_VIEW'],
  evaluated_at: new Date().toISOString(),
});

describe('AuthorizationEngine', () => {
  it('aggregates roles per scope, modules and de-duplicated permissions', () => {
    const result = AuthorizationEngine.aggregate([
      grant('RMS Registration Admin', 'RMS_REGISTRATION', 'RMS_REGISTRATION_VIEW'),
      grant('RMS Viewer', 'RMS_REGISTRATION', 'RMS_REGISTRATION_VIEW'),
      grant('RMS Registration Admin', 'RMS_REPORTS', 'RMS_REPORTS_VIEW'),
    ]);
    expect(result.roles.map((r) => r.role_name)).toEqual(['RMS Registration Admin', 'RMS Viewer']);
    expect(result.permissions).toEqual(['RMS_REGISTRATION_VIEW', 'RMS_REPORTS_VIEW']);
    expect(result.modules.map((m) => m.code)).toEqual(['RMS_REGISTRATION', 'RMS_REPORTS']);
  });

  it('allows a held permission and checks the module when given', () => {
    expect(AuthorizationEngine.decide(granted(), 'RMS_REGISTRATION_VIEW')).toEqual({ allowed: true });
    expect(AuthorizationEngine.decide(granted(), 'RMS_REGISTRATION_VIEW', 'RMS_REGISTRATION')).toEqual({ allowed: true });
    expect(AuthorizationEngine.decide(granted(), 'RMS_REGISTRATION_VIEW', 'RMS_REPORTS')).toEqual({ allowed: false, reason: 'MODULE_MISMATCH' });
  });

  it('denies permissions the user does not hold', () => {
    expect(AuthorizationEngine.decide(granted(), 'RMS_REGISTRATION_DELETE')).toEqual({ allowed: false, reason: 'PERMISSION_DENIED' });
  });

  it('propagates context denials (deny by default)', () => {
    const denied: EffectiveAccess = { ...granted(), access: 'DENIED', reason: 'USER_INACTIVE' };
    expect(AuthorizationEngine.decide(denied, 'RMS_REGISTRATION_VIEW')).toEqual({ allowed: false, reason: 'USER_INACTIVE' });
  });
});
