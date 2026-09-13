import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CheckResponse {
  @ApiProperty() allowed: boolean;
  @ApiPropertyOptional() its_id?: string;
  @ApiPropertyOptional() client_id?: string;
  @ApiPropertyOptional() permission?: string;
  @ApiPropertyOptional({ example: 'PERMISSION_DENIED' }) reason?: string;
}
