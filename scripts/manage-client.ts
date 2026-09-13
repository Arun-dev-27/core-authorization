/**
 * Operator CLI for a federation client's embed origins and callback / logout URIs.
 * Runs the same ClientsService as the HTTP API (same validation, same ACTIVE-client guards, audit rows,
 * cache invalidation). Use it from a bastion / CI job with database access; everyone else uses the API
 * with a CORE workspace token.
 *
 *   npm run client -- show      <client_id>
 *   npm run client -- origins   list   <client_id>
 *   npm run client -- origins   add    <client_id> <origin>
 *   npm run client -- origins   remove <client_id> <origin>
 *   npm run client -- callbacks list   <client_id>
 *   npm run client -- callbacks add    <client_id> <uri> [--type CALLBACK|BACK_CHANNEL_LOGOUT|POST_LOGOUT_REDIRECT] [--primary]
 *   npm run client -- callbacks remove <client_id> <uri> [--type ...]
 *
 * Identity Federation picks the change up within CLIENT_CACHE_TTL_SECONDS, or immediately via
 * POST /federation/clients/<client_id>/refresh.
 */
import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { userInfo } from 'node:os';
import { parseArgs } from 'node:util';
import { NestFactory } from '@nestjs/core';
import { loadEnvFiles } from '@config/configuration';
import { URI_TYPES, UriType } from '@common/constants/client.constants';
import { CLIENT_ID } from '@common/constants/validation.constants';
import { requestContext } from '@common/logging/request-context';
import { ClientsService } from '@modules/clients/services/clients.service';
import { AppModule } from '../src/app.module';

const USAGE = `usage:
  npm run client -- show <client_id>
  npm run client -- origins list|add|remove <client_id> [origin]
  npm run client -- callbacks list|add|remove <client_id> [uri] [--type CALLBACK|BACK_CHANNEL_LOGOUT|POST_LOGOUT_REDIRECT] [--primary]`;

async function main() {
  loadEnvFiles();
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: { type: { type: 'string' }, primary: { type: 'boolean', default: false } },
  });
  const [resource, second, third, fourth] = positionals;
  const action = resource === 'show' ? 'show' : second;
  const clientId = resource === 'show' ? second : third;
  const value = resource === 'show' ? undefined : fourth;

  if (!['show', 'origins', 'callbacks'].includes(resource ?? '') || !clientId) throw new Error(USAGE);
  if (!CLIENT_ID.test(clientId)) throw new Error(`invalid client_id '${clientId}'`);
  if (resource !== 'show' && !['list', 'add', 'remove'].includes(action ?? '')) throw new Error(USAGE);
  if ((action === 'add' || action === 'remove') && !value) throw new Error(`${resource} ${action} needs a value\n${USAGE}`);
  const uriType = (values.type ?? 'CALLBACK') as UriType;
  if (!URI_TYPES.includes(uriType)) throw new Error(`--type must be one of ${URI_TYPES.join(', ')}`);

  const app = await NestFactory.createApplicationContext(AppModule, { logger: ['error', 'warn'] });
  try {
    const clients = app.get(ClientsService, { strict: false });
    const actor = `cli:${userInfo().username}`;
    const result = await requestContext.run({ correlationId: randomUUID(), actor }, async () => {
      if (resource === 'show') return clients.getConfig(clientId);
      if (resource === 'origins') {
        if (action === 'add') return clients.addOrigin(clientId, value!);
        if (action === 'remove') return clients.removeOrigin(clientId, value!);
        return clients.listOrigins(clientId);
      }
      if (action === 'add') return clients.addCallback(clientId, { uri: value!, uri_type: uriType, is_primary: values.primary });
      if (action === 'remove') return clients.removeCallback(clientId, value!, uriType);
      return clients.listCallbacks(clientId);
    });
    console.log(JSON.stringify(result, null, 2));
    if (action === 'add' || action === 'remove') {
      console.log(`\n${resource} ${action} done by ${actor}. Identity Federation applies it within CLIENT_CACHE_TTL_SECONDS,`);
      console.log(`or immediately: POST <identity>/federation/clients/${clientId}/refresh (CORE workspace token, audience "identity").`);
    }
  } finally {
    await app.close();
  }
}

main().catch((error: unknown) => {
  const err = error as { code?: string; message?: string };
  console.error(err.code ? `${err.code}: ${err.message}` : (err.message ?? error));
  process.exit(1);
});
