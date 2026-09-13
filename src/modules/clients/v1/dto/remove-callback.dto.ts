import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, MaxLength } from 'class-validator';
import { URI_TYPES, UriType } from '@common/constants/client.constants';

/** DELETE /clients/:clientId/callbacks accepts `?uri=&uri_type=` or this JSON body. */
export class RemoveCallbackDto {
  @ApiPropertyOptional({ example: 'http://localhost:3000/auth/core/callback' })
  @IsOptional()
  @IsString()
  @MaxLength(2048)
  uri?: string;

  @ApiPropertyOptional({ enum: URI_TYPES, default: 'CALLBACK' })
  @IsOptional()
  @IsIn(URI_TYPES)
  uri_type?: UriType;
}
