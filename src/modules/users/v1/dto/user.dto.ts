import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsIn, IsOptional, IsString, IsUUID, Length, Matches, ValidateIf } from 'class-validator';
import { SCOPE_LEVELS, ScopeLevel, USER_STATUSES, UserStatus } from '@common/constants/rbac.constants';
import { ITS_ID } from '@common/constants/validation.constants';

/** No password/credential field exists; forbidNonWhitelisted rejects any attempt to send one. */
export class CreateUserDto {
  @ApiProperty({ example: '31189012', description: 'ITS ID is the user ID' })
  @Matches(ITS_ID)
  its_id: string;

  @ApiProperty({ example: 'Burhan' })
  @IsString()
  @Length(1, 256)
  name: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsEmail()
  @Length(3, 256)
  email?: string;

  @ApiPropertyOptional({ enum: USER_STATUSES, default: 'active' })
  @IsOptional()
  @IsIn(USER_STATUSES)
  status?: UserStatus;
}

export class UpdateUserDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @Length(1, 256)
  name?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsEmail()
  @Length(3, 256)
  email?: string;

  @ApiPropertyOptional({ enum: USER_STATUSES })
  @IsOptional()
  @IsIn(USER_STATUSES)
  status?: UserStatus;
}

export class SyncUserDto {
  @ApiProperty({ example: '30337752' })
  @Matches(ITS_ID)
  its_id: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @Length(1, 256)
  name?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsEmail()
  @Length(3, 256)
  email?: string;

  @ApiPropertyOptional({ enum: USER_STATUSES })
  @IsOptional()
  @IsIn(USER_STATUSES)
  status?: UserStatus;
}

export class UserRoleDto {
  @ApiProperty({ example: '31267890' })
  @Matches(ITS_ID)
  its_id: string;

  @ApiProperty()
  @IsUUID()
  role_id: string;

  @ApiProperty({ enum: SCOPE_LEVELS, example: 'UTILITY' })
  @IsIn(SCOPE_LEVELS)
  scope_type: ScopeLevel;

  @ApiPropertyOptional({ description: 'NULL for CORE, else bu_id or utility_id', nullable: true })
  @ValidateIf((o: UserRoleDto) => o.scope_type !== 'CORE' || (o.scope_id !== undefined && o.scope_id !== null))
  @IsUUID()
  scope_id?: string | null;
}
