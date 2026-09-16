import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsISO8601, IsOptional, IsString, IsUUID, Matches, MaxLength, ValidateIf } from 'class-validator';
import { SCOPE_LEVELS, ScopeLevel } from '@common/constants/rbac.constants';
import { ITS_ID } from '@common/constants/validation.constants';

/** The federation session id Identity puts in its assertions and access tokens. */
export const CORE_SID = /^[A-Za-z0-9._~-]{8,128}$/;

/**
 * Opaque local session token: base64url random, no dots, so a JWT (which always has two dots)
 * can never be presented here. 32 bytes of randomness is 43 characters.
 */
export const OPAQUE_SESSION_TOKEN = /^[A-Za-z0-9_-]{43,128}$/;

export class RecordSessionDto {
  @ApiProperty({ example: '31267890' })
  @Matches(ITS_ID)
  its_id: string;

  @ApiProperty({ description: 'Role of the workspace selected at sign-in (public.roles.role_id)' })
  @IsUUID()
  role_id: string;

  @ApiProperty({ enum: SCOPE_LEVELS })
  @IsIn(SCOPE_LEVELS)
  scope_type: ScopeLevel;

  @ApiPropertyOptional({ nullable: true })
  @ValidateIf((o: RecordSessionDto) => o.scope_type !== 'CORE' || (o.scope_id !== undefined && o.scope_id !== null))
  @IsUUID()
  scope_id?: string | null;

  @ApiProperty({ example: 'sid_NxMTq6C6u1JvyBgTKF8Yn9Te', description: 'Identity federation session id' })
  @Matches(CORE_SID)
  core_sid: string;

  @ApiProperty({ example: 'rms-web-dev', description: 'The validated client_id this session belongs to' })
  @IsString()
  @MaxLength(255)
  aud: string;

  @ApiProperty({ description: 'Opaque random local session token - never an assertion, access token, refresh token or JWT' })
  @Matches(OPAQUE_SESSION_TOKEN)
  session_token: string;

  @ApiProperty({ example: '2026-09-16T12:00:00.000Z' })
  @IsISO8601()
  expires_at: string;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(45)
  ip_address?: string | null;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(512)
  user_agent?: string | null;
}
