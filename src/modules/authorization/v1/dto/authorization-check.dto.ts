import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, Matches } from 'class-validator';
import { MODULE_CODE, PERMISSION_CODE } from '@common/constants/validation.constants';
import { EffectivePermissionsDto } from './effective-permissions.dto';

export class AuthorizationCheckDto extends EffectivePermissionsDto {
  @ApiPropertyOptional({ example: 'RMS_REGISTRATION' })
  @IsOptional()
  @Matches(MODULE_CODE)
  module?: string;

  @ApiProperty({ example: 'RMS_REGISTRATION_VIEW' })
  @Matches(PERMISSION_CODE)
  permission: string;
}
