import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsInt, IsOptional, IsString, Length, Matches } from 'class-validator';

export class CreateEnvironmentDto {
  @ApiProperty({ example: 'UAT' })
  @Matches(/^[A-Z0-9_]{2,16}$/)
  code: string;

  @ApiProperty({ example: 'User Acceptance Testing' })
  @IsString()
  @Length(2, 100)
  name: string;

  @ApiPropertyOptional({ default: false })
  @IsOptional()
  @IsBoolean()
  is_production?: boolean;

  @ApiPropertyOptional({ default: 0 })
  @IsOptional()
  @IsInt()
  sort_order?: number;
}
