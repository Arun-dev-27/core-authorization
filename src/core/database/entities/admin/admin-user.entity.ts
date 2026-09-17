import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { USER_STATUS, type UserStatus } from './admin-rbac.enums';
import { UserRole } from './user-role.entity';

/**
 * EXISTING admin_db table `users`. its_id is the identity_db users.mumin_id of the same person.
 * This service only reads it, apart from the login bookkeeping the table provides for
 * (last_login_at, has_been_active, INVITED -> ACTIVE on first sign-in).
 */
@Entity({ name: 'users' })
export class AdminUser {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'its_id', type: 'varchar', length: 8, nullable: true })
  itsId: string | null;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'varchar', length: 255 })
  email: string;

  @Column({ name: 'mobile_number', type: 'varchar', length: 30, nullable: true })
  mobileNumber: string | null;

  @Column({ type: 'enum', enum: USER_STATUS, enumName: 'user_status' })
  status: UserStatus;

  @Column({ name: 'has_been_active', type: 'boolean' })
  hasBeenActive: boolean;

  @Column({ name: 'last_login_at', type: 'timestamptz', nullable: true })
  lastLoginAt: Date | null;

  @Column({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => UserRole, (userRole) => userRole.user)
  userRoles: UserRole[];
}
