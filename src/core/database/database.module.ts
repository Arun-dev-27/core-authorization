import { Global, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppConfig } from '@config/config.module';
import { buildDataSourceOptions } from './data-source-options';
import { ADMIN_DB_ENTITIES } from './entities';
import { AdminSchemaCheck } from './admin-schema.check';
import { AdminRbacRepository } from './repositories/admin-rbac.repository';

/**
 * The authorization database connection. The Core Admin session flow uses TypeORM entities and AdminRbacRepository
 * over the EXISTING admin_db tables; synchronize and migrations are off, so TypeORM never creates or alters a table.
 * (The older catalog modules of this service still use parameterised SQL through the same DataSource.)
 */
@Global()
@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [AppConfig],
      useFactory: (config: AppConfig) => buildDataSourceOptions(config.env),
    }),
    TypeOrmModule.forFeature(ADMIN_DB_ENTITIES),
  ],
  providers: [AdminSchemaCheck, AdminRbacRepository],
  exports: [TypeOrmModule, AdminRbacRepository],
})
export class DatabaseModule {}
