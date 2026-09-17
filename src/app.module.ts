import { Module } from '@nestjs/common';
import { ConfigModule } from '@config/config.module';
import { AuditModule } from '@core/audit/audit.module';
import { RedisModule } from '@core/cache/redis.module';
import { DatabaseModule } from '@core/database/database.module';
import { HealthModule } from '@core/health/health.module';
import { AuthModule } from '@modules/auth/auth.module';
import { AuthorizationModule } from '@modules/authorization/authorization.module';
import { SigningModule } from '@modules/signing/signing.module';

/**
 * Authorization over the EXISTING admin_db: a verified core assertion becomes a local session scoped to one of the
 * user's existing roles, and that session's module/action/tenant permissions are enforced.
 *
 * The catalog modules (clients, applications, business units, utilities, environments, modules, roles, users, me,
 * federation directory) were removed: they read tables the existing admin_db does not contain.
 */
@Module({
  imports: [
    ConfigModule,
    DatabaseModule,
    RedisModule,
    AuditModule,
    AuthModule,
    SigningModule,
    HealthModule,
    AuthorizationModule,
  ],
})
export class AppModule {}
