import { ApiProperty } from '@nestjs/swagger';
import { IsString, Length } from 'class-validator';

export class VerifyAssertionDto {
  @ApiProperty({ description: 'Complete compact core_assertion (header.payload.signature) received by the browser from core-authentication.' })
  @IsString()
  @Length(1, 8192)
  core_assertion: string;
}
