import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, Matches } from 'class-validator';
import { UUID } from '@common/constants/validation.constants';

/** modules.code / permission_actions.code are varchar(20); matched case-insensitively. */
const RBAC_CODE = /^[A-Za-z][A-Za-z0-9_]{0,19}$/;

export class CheckSessionPermissionDto {
  @ApiProperty({ example: 'USR', description: 'modules.code' })
  @Matches(RBAC_CODE)
  module: string;

  @ApiProperty({ example: 'UPDATE', description: 'permission_actions.code (CREATE, READ, UPDATE, APPROVE)' })
  @Matches(RBAC_CODE)
  action: string;

  @ApiPropertyOptional({ description: 'Tenant the operation targets. Omit to act within the session role\'s own scope.' })
  @IsOptional()
  @Matches(UUID)
  tenant_id?: string;
}
