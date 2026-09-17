import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { ROLE_LEVEL, type RoleLevel } from './admin-rbac.enums';
import { AdminUser } from './admin-user.entity';
import { Role } from './role.entity';
import { Tenant } from './tenant.entity';

/** EXISTING admin_db table `user_roles`: which role a user holds, per tenant. Read-only for this service. */
@Entity({ name: 'user_roles' })
export class UserRole {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @ManyToOne(() => AdminUser, (user) => user.userRoles)
  @JoinColumn({ name: 'user_id' })
  user: AdminUser;

  @Column({ name: 'role_id', type: 'uuid' })
  roleId: string;

  @ManyToOne(() => Role)
  @JoinColumn({ name: 'role_id' })
  role: Role;

  @Column({ name: 'tenant_id', type: 'uuid', nullable: true })
  tenantId: string | null;

  @ManyToOne(() => Tenant, { nullable: true })
  @JoinColumn({ name: 'tenant_id' })
  tenant: Tenant | null;

  @Column({ name: 'role_level', type: 'enum', enum: ROLE_LEVEL, enumName: 'role_level' })
  roleLevel: RoleLevel;

  @Column({ name: 'assigned_at', type: 'timestamptz' })
  assignedAt: Date;
}
