import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, IsUUID, Length } from 'class-validator';
import { RECORD_STATUSES, RecordStatus } from '@common/constants/rbac.constants';

export class CreateBusinessUnitDto {
  @ApiProperty({ example: 'RMS' })
  @IsString()
  @Length(2, 200)
  name: string;

  @ApiPropertyOptional({ enum: RECORD_STATUSES, default: 'active' })
  @IsOptional()
  @IsIn(RECORD_STATUSES)
  status?: RecordStatus;

  @ApiPropertyOptional({ description: 'Only for ADMIN service principals; users always create in their own tenant' })
  @IsOptional()
  @IsUUID()
  tenant_id?: string;
}

export class UpdateBusinessUnitDto {
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

export class BusinessUnitQueryDto {
  @ApiPropertyOptional({ enum: RECORD_STATUSES })
  @IsOptional()
  @IsIn(RECORD_STATUSES)
  status?: RecordStatus;
}
