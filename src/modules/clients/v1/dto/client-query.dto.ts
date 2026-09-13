import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, Matches } from 'class-validator';
import { CODE_LOWER } from '@common/constants/validation.constants';
import { CLIENT_STATUSES, ClientStatus } from '../../services/client-lifecycle';

export class ClientQueryDto {
  @ApiPropertyOptional({ example: 'rms' })
  @IsOptional()
  @Matches(CODE_LOWER)
  application?: string;

  @ApiPropertyOptional({ example: 'PROD' })
  @IsOptional()
  @Matches(/^[A-Z0-9_]{2,16}$/)
  environment?: string;

  @ApiPropertyOptional({ enum: CLIENT_STATUSES })
  @IsOptional()
  @IsIn(CLIENT_STATUSES)
  status?: ClientStatus;
}
