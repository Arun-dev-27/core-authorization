export const URI_TYPES = ['CALLBACK', 'BACK_CHANNEL_LOGOUT', 'POST_LOGOUT_REDIRECT'] as const;
export type UriType = (typeof URI_TYPES)[number];
