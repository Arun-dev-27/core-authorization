import { ApiProperty } from '@nestjs/swagger';
import { Matches } from 'class-validator';
import { UUID } from '@common/constants/validation.constants';

const PENDING_TOKEN = /^[A-Za-z0-9_-]{16,128}$/;

export class SelectRoleDto {
  @ApiProperty({ description: 'pending_token returned by POST /authorization/session when selection_required is true.' })
  @Matches(PENDING_TOKEN)
  pending_token: string;

  @ApiProperty({ description: 'One of the role_id values from that same response.' })
  @Matches(UUID)
  role_id: string;
}
