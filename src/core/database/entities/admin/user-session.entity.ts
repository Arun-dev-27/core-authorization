import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { AdminUser } from './admin-user.entity';
import { Role } from './role.entity';

/** EXISTING admin_db table `user_sessions`: the local session a verified core assertion establishes, scoped to one role. */
@Entity({ name: 'user_sessions' })
export class UserSession {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @ManyToOne(() => AdminUser)
  @JoinColumn({ name: 'user_id' })
  user: AdminUser;

  @Column({ name: 'role_id', type: 'uuid' })
  roleId: string;

  @ManyToOne(() => Role)
  @JoinColumn({ name: 'role_id' })
  role: Role;

  /** sid of the core assertion this session was established from. */
  @Column({ name: 'core_sid', type: 'text', nullable: true })
  coreSid: string | null;

  /** client_id (aud) of that assertion. */
  @Column({ type: 'varchar', length: 255, nullable: true })
  aud: string | null;

  @Column({ name: 'session_token', type: 'text' })
  sessionToken: string;

  @Column({ name: 'ip_address', type: 'inet', nullable: true })
  ipAddress: string | null;

  @Column({ name: 'user_agent', type: 'text', nullable: true })
  userAgent: string | null;

  @Column({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @Column({ name: 'revoked_at', type: 'timestamptz', nullable: true })
  revokedAt: Date | null;
}
