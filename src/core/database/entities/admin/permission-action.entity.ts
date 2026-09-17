import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/** EXISTING admin_db table `permission_actions` (CREATE, READ, UPDATE, APPROVE). Read-only for this service. */
@Entity({ name: 'permission_actions' })
export class PermissionAction {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 20 })
  code: string;

  @Column({ type: 'varchar', length: 100 })
  name: string;

  @Column({ name: 'display_order', type: 'integer' })
  displayOrder: number;
}
