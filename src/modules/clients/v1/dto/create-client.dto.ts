import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ArrayMaxSize, IsArray, IsIn, IsOptional, IsString, Length, Matches, MaxLength } from 'class-validator';
import { CLIENT_ID, CODE_LOWER } from '@common/constants/validation.constants';
import { AUTHENTICATION_MODES, AuthenticationMode, CLIENT_TYPES } from '../../services/client-lifecycle';

export class CreateClientDto {
  @ApiProperty({ example: 'rms-web-prod', description: 'Globally unique; never reused across environments' })
  @Matches(CLIENT_ID)
  client_id: string;

  @ApiProperty({ example: 'rms' })
  @Matches(CODE_LOWER)
  application_code: string;

  @ApiProperty({ example: 'PROD' })
  @Matches(/^[A-Z0-9_]{2,16}$/)
  environment_code: string;

  @ApiPropertyOptional({ example: 'RMS Web (Production)' })
  @IsOptional()
  @IsString()
  @Length(2, 200)
  name?: string;

  @ApiProperty({ enum: CLIENT_TYPES, example: 'WEB' })
  @IsIn(CLIENT_TYPES)
  client_type: (typeof CLIENT_TYPES)[number];

  @ApiProperty({ enum: AUTHENTICATION_MODES, example: 'EMBEDDED' })
  @IsIn(AUTHENTICATION_MODES)
  authentication_mode: AuthenticationMode;

  @ApiPropertyOptional({ example: ['https://rms.example.com'] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  allowed_embed_origins?: string[];

  @ApiPropertyOptional({ example: ['https://rms.example.com/auth/core/callback'] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  callback_uris?: string[];

  @ApiPropertyOptional({ example: 'https://rms.example.com/auth/core/logout' })
  @IsOptional()
  @IsString()
  @MaxLength(2048)
  back_channel_logout_uri?: string;

  @ApiPropertyOptional({ example: ['https://rms.example.com/logout/callback'] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  post_logout_redirect_uris?: string[];

  @ApiPropertyOptional({ example: 'https://rms.example.com/auth/core/login', description: 'Used by the Core Portal launcher' })
  @IsOptional()
  @IsString()
  @MaxLength(2048)
  initiate_login_uri?: string;
}
