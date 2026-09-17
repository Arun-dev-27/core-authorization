import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { CoreModule } from './core-module.entity';
import { PermissionAction } from './permission-action.entity';

/** EXISTING admin_db table `module_actions`: an action offered on a module, and at which role levels. Read-only here. */
@Entity({ name: 'module_actions' })
export class ModuleAction {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'module_id', type: 'uuid' })
  moduleId: string;

  @ManyToOne(() => CoreModule)
  @JoinColumn({ name: 'module_id' })
  module: CoreModule;

  @Column({ name: 'action_id', type: 'uuid' })
  actionId: string;

  @ManyToOne(() => PermissionAction)
  @JoinColumn({ name: 'action_id' })
  action: PermissionAction;

  @Column({ name: 'applies_to_core', type: 'boolean' })
  appliesToCore: boolean;

  @Column({ name: 'applies_to_tenant', type: 'boolean' })
  appliesToTenant: boolean;
}
