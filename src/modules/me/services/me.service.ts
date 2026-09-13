import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { DomainError } from '@common/errors/domain-error';
import { queryOne } from '@core/database/sql';
import { RbacService } from '@modules/rbac/services/rbac.service';
import { ActorContext } from '@shared/types/principal.types';

@Injectable()
export class MeService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly rbac: RbacService,
  ) {}

  /** Workspaces for the Select Workspace screen. requires_scope_selection = assignments.length > 1. */
  async assignments(itsId: string) {
    const user = await queryOne<{ name: string }>(this.db, `SELECT name FROM users WHERE its_id = $1 AND status = 'active'`, [itsId]);
    if (!user) throw DomainError.notFound('User', itsId);
    const assignments = (await this.rbac.listAssignments(itsId)).map((a) => this.rbac.toActiveScope(a));
    return { its_id: itsId, name: user.name, requires_scope_selection: assignments.length > 1, assignments };
  }

  async me(actor: ActorContext) {
    const user = await queryOne<{ name: string; email: string | null }>(this.db, `SELECT name, email FROM users WHERE its_id = $1`, [actor.itsId]);
    return {
      its_id: actor.itsId,
      name: user?.name ?? null,
      email: user?.email ?? null,
      active_scope: { role_id: actor.roleId, role_name: actor.roleName, scope_type: actor.scopeType, scope_id: actor.scopeId, scope_name: actor.scopeName },
    };
  }

  /** { MODULE_CODE: [actions] } for the active workspace only. Missing key = module hidden. */
  permissions(actor: ActorContext) {
    return this.rbac.permissionMap(actor.roleId!);
  }
}
