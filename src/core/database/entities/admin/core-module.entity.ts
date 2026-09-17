import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/** EXISTING admin_db table `modules` (Role Management, User Management, ...). Read-only for this service. */
@Entity({ name: 'modules' })
export class CoreModule {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 20 })
  code: string;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ name: 'applies_to_core', type: 'boolean' })
  appliesToCore: boolean;

  @Column({ name: 'applies_to_tenant', type: 'boolean' })
  appliesToTenant: boolean;

  @Column({ name: 'display_order', type: 'integer' })
  displayOrder: number;
}
