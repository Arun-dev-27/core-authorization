import { Module } from '@nestjs/common';
import { UsersServicesModule } from '../users-services.module';
import { UsersController, UserRolesController } from './users.controller';

/** Users and role assignments — v1 HTTP edge. */
@Module({
  imports: [UsersServicesModule],
  controllers: [UsersController, UserRolesController],
})
export class UsersV1Module {}
