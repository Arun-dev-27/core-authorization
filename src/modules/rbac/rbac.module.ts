import { Global, Module } from '@nestjs/common';
import { RbacService } from './services/rbac.service';

/** Core RBAC rules (workspaces, scopes, escalation checks) shared by every feature. */
@Global()
@Module({
  providers: [RbacService],
  exports: [RbacService],
})
export class RbacModule {}
