import { Module } from '@nestjs/common';
import { UsersServicesModule } from './users-services.module';
import { UsersV1Module } from './v1/users-v1.module';

/** Users and role assignments — feature aggregator. */
@Module({
  imports: [UsersServicesModule, UsersV1Module],
  exports: [UsersServicesModule],
})
export class UsersModule {}
