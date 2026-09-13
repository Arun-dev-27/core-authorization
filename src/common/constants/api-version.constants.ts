import { VERSION_NEUTRAL } from '@nestjs/common';

/**
 * v1 routes are served at /v1/<path> AND at the unversioned /<path> (the published contract
 * used by Identity Federation and BU backends). A future v2 edge declares `version: '2'` only.
 */
export const API_V1: Array<string | typeof VERSION_NEUTRAL> = ['1', VERSION_NEUTRAL];
