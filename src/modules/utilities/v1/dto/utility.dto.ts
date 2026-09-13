import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, IsUUID, Length } from 'class-validator';
import { RECORD_STATUSES, RecordStatus } from '@common/constants/rbac.constants';

export class CreateUtilityDto {
  @ApiProperty({ description: 'Parent business unit' })
  @IsUUID()
  bu_id: string;

  @ApiProperty({ example: 'Helpdesk' })
  @IsString()
  @Length(2, 200)
  name: string;

  @ApiPropertyOptional({ enum: RECORD_STATUSES, default: 'active' })
  @IsOptional()
  @IsIn(RECORD_STATUSES)
  status?: RecordStatus;
}

export class UpdateUtilityDto {
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

export class UtilityQueryDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsUUID()
  bu_id?: string;

  @ApiPropertyOptional({ enum: RECORD_STATUSES })
  @IsOptional()
  @IsIn(RECORD_STATUSES)
  status?: RecordStatus;
}
