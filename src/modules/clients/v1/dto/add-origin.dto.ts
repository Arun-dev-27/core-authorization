import { ApiProperty } from '@nestjs/swagger';
import { IsString, MaxLength } from 'class-validator';

export class AddOriginDto {
  @ApiProperty({ example: 'https://rms.example.com' })
  @IsString()
  @MaxLength(512)
  origin: string;
}
