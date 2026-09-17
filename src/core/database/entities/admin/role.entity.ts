import { Column, Entity, JoinColumn, ManyToOne, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { ROLE_LEVEL, ROLE_STATUS, type RoleLevel, type RoleStatus } from './admin-rbac.enums';
import { RolePermission } from './role-permission.entity';
import { Tenant } from './tenant.entity';

/** EXISTING admin_db table `roles`. tenant_id is null only for the platform-wide CORE_ADMIN role. Read-only here. */
@Entity({ name: 'roles' })
export class Role {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'role_level', type: 'enum', enum: ROLE_LEVEL, enumName: 'role_level' })
  roleLevel: RoleLevel;

  @Column({ name: 'tenant_id', type: 'uuid', nullable: true })
  tenantId: string | null;

  @ManyToOne(() => Tenant, { nullable: true })
  @JoinColumn({ name: 'tenant_id' })
  tenant: Tenant | null;

  @Column({ name: 'role_code', type: 'varchar', length: 50 })
  roleCode: string;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'text', nullable: true })
  description: string | null;

  @Column({ type: 'enum', enum: ROLE_STATUS, enumName: 'role_status' })
  status: RoleStatus;

  @Column({ name: 'is_full_access', type: 'boolean' })
  isFullAccess: boolean;

  @OneToMany(() => RolePermission, (permission) => permission.role)
  permissions: RolePermission[];
}
