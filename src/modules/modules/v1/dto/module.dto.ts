import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ArrayMaxSize, IsArray, IsIn, IsOptional, IsString, Length, Matches } from 'class-validator';
import { PERMISSION_ACTIONS, PermissionAction } from '@common/constants/rbac.constants';
import { APPLICATION_CODE, MODULE_CODE } from '@common/constants/validation.constants';

export class CreateModuleDto {
  @ApiProperty({ example: 'RMS_REGISTRATION' })
  @Matches(MODULE_CODE)
  module_code: string;

  @ApiProperty({ example: 'RMS Registration' })
  @IsString()
  @Length(2, 200)
  module_name: string;

  @ApiPropertyOptional({ example: 'rms', description: 'Owning application; omit for a Core Portal module' })
  @IsOptional()
  @Matches(APPLICATION_CODE)
  application_code?: string;

  @ApiPropertyOptional({ enum: PERMISSION_ACTIONS, isArray: true, example: ['view', 'create', 'edit'] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(6)
  @IsIn(PERMISSION_ACTIONS, { each: true })
  actions?: PermissionAction[];
}

export class ModuleQueryDto {
  @ApiPropertyOptional({ example: 'rms' })
  @IsOptional()
  @Matches(APPLICATION_CODE)
  application_code?: string;

  @ApiPropertyOptional({ enum: ['true', 'false'] })
  @IsOptional()
  @IsIn(['true', 'false'])
  is_default?: 'true' | 'false';
}

export class CreatePermissionDto {
  @ApiProperty({ example: 'ROLE_MGMT' })
  @Matches(MODULE_CODE)
  module_code: string;

  @ApiProperty({ enum: PERMISSION_ACTIONS, example: 'export' })
  @IsIn(PERMISSION_ACTIONS)
  action: PermissionAction;
}

export class PermissionQueryDto {
  @ApiPropertyOptional({ example: 'ROLE_MGMT' })
  @IsOptional()
  @Matches(MODULE_CODE)
  module_code?: string;
}
