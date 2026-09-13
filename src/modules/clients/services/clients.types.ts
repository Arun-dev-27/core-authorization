import type { UriType } from '@common/constants/client.constants';
import type { AuthenticationMode, CLIENT_TYPES, ClientStatus } from './client-lifecycle';

/** Version-agnostic input for the service layer (the v1 DTO satisfies it structurally). */
export interface AddCallbackInput {
  uri: string;
  uri_type?: UriType;
  is_primary?: boolean;
}

/** Version-agnostic input for the service layer (the v1 DTO satisfies it structurally). */
export interface ClientQueryInput {
  application?: string;
  environment?: string;
  status?: ClientStatus;
}

/** Version-agnostic input for the service layer (the v1 DTO satisfies it structurally). */
export interface CreateClientInput {
  client_id: string;
  application_code: string;
  environment_code: string;
  name?: string;
  client_type: (typeof CLIENT_TYPES)[number];
  authentication_mode: AuthenticationMode;
  allowed_embed_origins?: string[];
  callback_uris?: string[];
  back_channel_logout_uri?: string;
  post_logout_redirect_uris?: string[];
  initiate_login_uri?: string;
}

/** Version-agnostic input for the service layer (the v1 DTO satisfies it structurally). */
export interface UpdateClientInput {
  status?: ClientStatus;
  reason?: string;
  name?: string;
  authentication_mode?: AuthenticationMode;
  back_channel_logout_uri?: string | null;
  initiate_login_uri?: string | null;
}
