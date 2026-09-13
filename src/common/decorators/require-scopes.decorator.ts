import { SetMetadata } from '@nestjs/common';
import { ApiScope } from '../constants/api-scopes.constants';

export const SCOPES_KEY = 'miqaat:scopes';

/** Caller must hold at least one of the listed scopes. ADMIN satisfies every scope. */
export const RequireScopes = (...scopes: ApiScope[]) => SetMetadata(SCOPES_KEY, scopes);
