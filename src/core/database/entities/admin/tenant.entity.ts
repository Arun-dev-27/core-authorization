import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { TENANT_STATUS, TENANT_TYPE, type TenantStatus, type TenantType } from './admin-rbac.enums';

/** EXISTING admin_db table `tenants` (Business Units and Utilities). Read-only for this service. */
@Entity({ name: 'tenants' })
export class Tenant {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'tenant_type', type: 'enum', enum: TENANT_TYPE, enumName: 'tenant_type' })
  tenantType: TenantType;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column({ type: 'enum', enum: TENANT_STATUS, enumName: 'tenant_status' })
  status: TenantStatus;
}
