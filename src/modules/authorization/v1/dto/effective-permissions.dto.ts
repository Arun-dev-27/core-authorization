import { ApiProperty } from '@nestjs/swagger';
import { Matches } from 'class-validator';
import { CLIENT_ID, ITS_ID } from '@common/constants/validation.constants';

export class EffectivePermissionsDto {
  @ApiProperty({ example: 'ITS12345' })
  @Matches(ITS_ID)
  its_id: string;

  @ApiProperty({ example: 'rms-web-prod' })
  @Matches(CLIENT_ID)
  client_id: string;
}
