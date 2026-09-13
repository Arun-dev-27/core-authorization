import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, MaxLength } from 'class-validator';

/** DELETE /clients/:clientId/origins accepts the origin as `?origin=` or in this JSON body. */
export class RemoveOriginDto {
  @ApiPropertyOptional({ example: 'http://localhost:3000' })
  @IsOptional()
  @IsString()
  @MaxLength(512)
  origin?: string;
}
