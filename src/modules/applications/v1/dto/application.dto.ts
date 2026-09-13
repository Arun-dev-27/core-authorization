import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, IsUUID, Length, Matches } from 'class-validator';
import { RECORD_STATUSES, RecordStatus } from '@common/constants/rbac.constants';
import { APPLICATION_CODE } from '@common/constants/validation.constants';

export class CreateApplicationDto {
  @ApiProperty({ example: 'hbs' })
  @Matches(APPLICATION_CODE)
  code: string;

  @ApiProperty({ example: 'HBS Web' })
  @IsString()
  @Length(2, 200)
  name: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @Length(0, 2000)
  description?: string;

  @ApiPropertyOptional({ description: 'Owning business unit' })
  @IsOptional()
  @IsUUID()
  bu_id?: string;

  @ApiPropertyOptional({ description: 'Owning utility' })
  @IsOptional()
  @IsUUID()
  utility_id?: string;

  @ApiPropertyOptional({ enum: RECORD_STATUSES, default: 'active' })
  @IsOptional()
  @IsIn(RECORD_STATUSES)
  status?: RecordStatus;
}

export class ApplicationQueryDto {
  @ApiPropertyOptional({ enum: RECORD_STATUSES })
  @IsOptional()
  @IsIn(RECORD_STATUSES)
  status?: RecordStatus;
}
