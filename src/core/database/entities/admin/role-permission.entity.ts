import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { ModuleAction } from './module-action.entity';
import { Role } from './role.entity';

/** EXISTING admin_db table `role_permissions`: a role granted one module action. Read-only for this service. */
@Entity({ name: 'role_permissions' })
export class RolePermission {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'role_id', type: 'uuid' })
  roleId: string;

  @ManyToOne(() => Role, (role) => role.permissions)
  @JoinColumn({ name: 'role_id' })
  role: Role;

  @Column({ name: 'module_action_id', type: 'uuid' })
  moduleActionId: string;

  @ManyToOne(() => ModuleAction)
  @JoinColumn({ name: 'module_action_id' })
  moduleAction: ModuleAction;
}
