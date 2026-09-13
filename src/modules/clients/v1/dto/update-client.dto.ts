import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, Length, MaxLength } from 'class-validator';
import { AUTHENTICATION_MODES, AuthenticationMode, CLIENT_STATUSES, ClientStatus } from '../../services/client-lifecycle';

export class UpdateClientDto {
  @ApiPropertyOptional({ enum: CLIENT_STATUSES })
  @IsOptional()
  @IsIn(CLIENT_STATUSES)
  status?: ClientStatus;

  @ApiPropertyOptional({ description: 'Reason recorded in client status history' })
  @IsOptional()
  @IsString()
  @Length(1, 1000)
  reason?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @Length(2, 200)
  name?: string;

  @ApiPropertyOptional({ enum: AUTHENTICATION_MODES })
  @IsOptional()
  @IsIn(AUTHENTICATION_MODES)
  authentication_mode?: AuthenticationMode;

  @ApiPropertyOptional({ nullable: true, description: 'null removes the back-channel logout URI' })
  @IsOptional()
  @IsString()
  @MaxLength(2048)
  back_channel_logout_uri?: string | null;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(2048)
  initiate_login_uri?: string | null;
}
