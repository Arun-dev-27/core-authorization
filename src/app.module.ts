import { Module } from '@nestjs/common';
import { ConfigModule } from '@config/config.module';
import { AuditModule } from '@core/audit/audit.module';
import { RedisModule } from '@core/cache/redis.module';
import { DatabaseModule } from '@core/database/database.module';
import { HealthModule } from '@core/health/health.module';
import { ApplicationsModule } from '@modules/applications/applications.module';
import { AuthModule } from '@modules/auth/auth.module';
import { AuthorizationModule } from '@modules/authorization/authorization.module';
import { BusinessUnitsModule } from '@modules/business-units/business-units.module';
import { ClientsModule } from '@modules/clients/clients.module';
import { EnvironmentsModule } from '@modules/environments/environments.module';
import { FederationModule } from '@modules/federation/federation.module';
import { MeModule } from '@modules/me/me.module';
import { ModulesModule } from '@modules/modules/modules.module';
import { RbacModule } from '@modules/rbac/rbac.module';
import { RolesModule } from '@modules/roles/roles.module';
import { TenantsModule } from '@modules/tenants/tenants.module';
import { UsersModule } from '@modules/users/users.module';
import { UtilitiesModule } from '@modules/utilities/utilities.module';

@Module({
  imports: [
    // app-wide infrastructure
    ConfigModule,
    DatabaseModule,
    RedisModule,
    AuditModule,
    RbacModule,
    AuthModule,
    HealthModule,
    // Core RBAC: tenants → business units → utilities; modules → permissions; roles; users × roles × scopes
    TenantsModule,
    BusinessUnitsModule,
    UtilitiesModule,
    ModulesModule,
    RolesModule,
    UsersModule,
    MeModule,
    // login federation: applications, environments, clients, decisions, internal API for Identity
    ApplicationsModule,
    EnvironmentsModule,
    ClientsModule,
    AuthorizationModule,
    FederationModule,
  ],
})
export class AppModule {}
