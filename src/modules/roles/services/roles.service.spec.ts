import type { DataSource } from 'typeorm';
import type { AuditService } from '@core/audit/audit.service';
import type { AuthzCacheService } from '@modules/authorization/services/authz-cache.service';
import type { RbacService } from '@modules/rbac/services/rbac.service';
import type { ActorContext } from '@shared/types/principal.types';
import { RolesService } from './roles.service';

const ROLE_ID = '6a1f0c7e-2b3d-4e5f-8a9b-0c1d2e3f4a5b';
const TENANT = '0f8e7d6c-5b4a-4938-8271-605f4e3d2c1b';
const actor = { kind: 'user', itsId: '30416234', tenantId: TENANT, isCore: true, scopeType: 'CORE', scopeId: null, permissions: 'ALL' } as unknown as ActorContext;

function setup() {
  const steps: string[] = [];
  const role = { role_id: ROLE_ID, tenant_id: TENANT, role_name: 'Zone Manager', scope_level: 'BUSINESS_UNIT', is_system_role: false };
  const db = {
    query: jest.fn(async (sql: string) => {
      steps.push(sql.trim().split(/\s+/)[0]);
      return [{ ...role, role_name: 'Zone Lead' }];
    }),
  };
  const rbac = {
    roleById: jest.fn().mockResolvedValue(role),
    assertTenant: jest.fn(),
    assertCanManageRoleLevel: jest.fn(),
    manageableLevels: jest.fn().mockReturnValue(['CORE', 'BUSINESS_UNIT', 'UTILITY']),
  };
  const cache = { invalidateAll: jest.fn(async () => void steps.push('INVALIDATE')) };
  const audit = { record: jest.fn(async () => void steps.push('AUDIT')) };
  const service = new RolesService(db as unknown as DataSource, rbac as unknown as RbacService, audit as unknown as AuditService, cache as unknown as AuthzCacheService);
  return { service, steps, cache };
}

describe('RolesService.rename', () => {
  it('invalidates the effective-permission cache right after the rename', async () => {
    const { service, steps, cache } = setup();
    await service.rename(actor, ROLE_ID, 'Zone Lead');
    expect(cache.invalidateAll).toHaveBeenCalledTimes(1);
    expect(steps.slice(0, 3)).toEqual(['UPDATE', 'INVALIDATE', 'AUDIT']);
  });

  it('surfaces a failed invalidation to the caller', async () => {
    const { service, cache } = setup();
    cache.invalidateAll.mockRejectedValueOnce(Object.assign(new Error('cache'), { code: 'CACHE_INVALIDATION_FAILED', status: 503 }));
    await expect(service.rename(actor, ROLE_ID, 'Zone Lead')).rejects.toMatchObject({ code: 'CACHE_INVALIDATION_FAILED' });
  });
});
