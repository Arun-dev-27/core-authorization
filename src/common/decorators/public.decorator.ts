import { SetMetadata } from '@nestjs/common';

export const PUBLIC_KEY = 'miqaat:public';
export const Public = () => SetMetadata(PUBLIC_KEY, true);
