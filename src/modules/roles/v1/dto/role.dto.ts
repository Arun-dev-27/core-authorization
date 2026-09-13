import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ArrayMaxSize, ArrayMinSize, IsArray, IsIn, IsOptional, IsString, IsUUID, Length, Matches } from 'class-validator';
import { SCOPE_LEVELS, ScopeLevel } from '@common/constants/rbac.constants';
import { PERMISSION_CODE } from '@common/constants/validation.constants';

export class CreateRoleDto {
  @ApiProperty({ example: 'Zone Manager' })
  @IsString()
  @Length(2, 200)
  role_name: string;

  @ApiProperty({ enum: SCOPE_LEVELS, example: 'UTILITY' })
  @IsIn(SCOPE_LEVELS)
  scope_level: ScopeLevel;

  @ApiPropertyOptional({ example: ['DASHBOARD_VIEW', 'TICKET_MGMT_VIEW', 'TICKET_MGMT_CREATE'] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(500)
  @Matches(PERMISSION_CODE, { each: true })
  permission_codes?: string[];

  @ApiPropertyOptional({ description: 'Only for ADMIN service principals' })
  @IsOptional()
  @IsUUID()
  tenant_id?: string;
}

export class UpdateRoleDto {
  @ApiProperty({ example: 'Zone Manager (North)' })
  @IsString()
  @Length(2, 200)
  role_name: string;
}

export class RoleQueryDto {
  @ApiPropertyOptional({ enum: SCOPE_LEVELS })
  @IsOptional()
  @IsIn(SCOPE_LEVELS)
  scope_level?: ScopeLevel;
}

export class RolePermissionsDto {
  @ApiProperty()
  @IsUUID()
  role_id: string;

  @ApiProperty({ example: ['TICKET_MGMT_EDIT'] })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(500)
  @Matches(PERMISSION_CODE, { each: true })
  permission_codes: string[];

  @ApiPropertyOptional({ enum: ['GRANT', 'REVOKE'], default: 'GRANT' })
  @IsOptional()
  @IsIn(['GRANT', 'REVOKE'])
  action?: 'GRANT' | 'REVOKE';
}
