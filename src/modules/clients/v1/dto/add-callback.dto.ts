import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsIn, IsOptional, IsString, MaxLength } from 'class-validator';
import { URI_TYPES, UriType } from '@common/constants/client.constants';

export class AddCallbackDto {
  @ApiProperty({ example: 'https://rms.example.com/auth/core/callback' })
  @IsString()
  @MaxLength(2048)
  uri: string;

  @ApiPropertyOptional({ enum: URI_TYPES, default: 'CALLBACK' })
  @IsOptional()
  @IsIn(URI_TYPES)
  uri_type?: UriType;

  @ApiPropertyOptional({ default: false })
  @IsOptional()
  @IsBoolean()
  is_primary?: boolean;
}
