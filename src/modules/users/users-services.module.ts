import { Module } from '@nestjs/common';
import { AuthorizationServicesModule } from '@modules/authorization/authorization-services.module';
import { UsersService } from './services/users.service';

/** Users and role assignments — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationServicesModule],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersServicesModule {}
