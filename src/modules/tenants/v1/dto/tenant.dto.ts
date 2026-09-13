import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, Length } from 'class-validator';
import { RECORD_STATUSES, RecordStatus } from '@common/constants/rbac.constants';

export class CreateTenantDto {
  @ApiProperty({ example: 'Miqaat' })
  @IsString()
  @Length(2, 200)
  name: string;

  @ApiPropertyOptional({ enum: RECORD_STATUSES, default: 'active' })
  @IsOptional()
  @IsIn(RECORD_STATUSES)
  status?: RecordStatus;
}

export class UpdateTenantDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @Length(2, 200)
  name?: string;

  @ApiPropertyOptional({ enum: RECORD_STATUSES })
  @IsOptional()
  @IsIn(RECORD_STATUSES)
  status?: RecordStatus;
}
