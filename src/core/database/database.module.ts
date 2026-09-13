import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppConfig } from '@config/config.module';
import { buildDataSourceOptions } from './data-source-options';

/**
 * Data access uses explicit, parameterised SQL through the TypeORM DataSource.
 * Schema changes are applied only through reviewed migrations (synchronize=false).
 */
@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [AppConfig],
      useFactory: (config: AppConfig) => buildDataSourceOptions(config.env),
    }),
  ],
})
export class DatabaseModule {}
