import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsUUID, Matches, ValidateIf } from 'class-validator';
import { SCOPE_LEVELS, ScopeLevel } from '@common/constants/rbac.constants';
import { ITS_ID } from '@common/constants/validation.constants';

export class ResolveAssignmentDto {
  @ApiProperty({ example: '31267890' })
  @Matches(ITS_ID)
  its_id: string;

  @ApiProperty()
  @IsUUID()
  role_id: string;

  @ApiProperty({ enum: SCOPE_LEVELS })
  @IsIn(SCOPE_LEVELS)
  scope_type: ScopeLevel;

  @ApiPropertyOptional({ nullable: true })
  @ValidateIf((o: ResolveAssignmentDto) => o.scope_type !== 'CORE' || (o.scope_id !== undefined && o.scope_id !== null))
  @IsUUID()
  scope_id?: string | null;
}
