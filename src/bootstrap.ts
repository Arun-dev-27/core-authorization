import helmet from '@fastify/helmet';
import { VERSION_NEUTRAL, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { Env, loadEnv } from '@config/configuration';
import { GlobalExceptionFilter } from '@common/filters/http-exception.filter';
import { PinoNestLogger, createLogger, genRequestId } from '@common/logging/logger';
import { requestContext } from '@common/logging/request-context';
import { AppModule } from './app.module';
import { configureClientIpHeader, configureSessionBinding } from '@common/security/session-binding';

export function buildOpenApiConfig() {
  return new DocumentBuilder()
    .setTitle('Miqaat Core Identity Authorization Service')
    .setDescription(
      'Dynamic Business Unit / Utility / Application / Environment / Module / Role / Permission model, client registry and server-side authorization checks. ' +
        'No API keys: every call carries an RS256 bearer JWT verified via JWKS - service tokens (typ client-authentication+jwt) from registered service principals, ' +
        'or administrator access tokens (typ at+jwt) issued by Identity Federation. Never stores credentials.',
    )
    .setVersion('1.0.0')
    .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT (RS256, verified via JWKS)' })
    .build();
}

export async function createApp(env: Env = loadEnv()): Promise<NestFastifyApplication> {
  const logger = createLogger(env.LOG_LEVEL);
  const adapter = new FastifyAdapter({
    loggerInstance: logger,
    trustProxy: env.TRUST_PROXY,
    genReqId: genRequestId,
    requestIdHeader: false,
    bodyLimit: 1_048_576,
  });

  // Set before any request is served, so session binding reads the same source everywhere.

  configureClientIpHeader(env.CLIENT_IP_HEADER ?? null);
  configureSessionBinding(env.SESSION_BINDING);

  const app = await NestFactory.create<NestFastifyApplication>(AppModule, adapter, { bufferLogs: true });
  app.useLogger(new PinoNestLogger(logger));

  const fastify = app.getHttpAdapter().getInstance();
  fastify.addHook('onRequest', (request, reply, done) => {
    void reply.header('x-request-id', request.id);
    requestContext.run({ correlationId: request.id }, done);
  });

  // /authorization/session[/me|/logout|/select] is called directly from a Business Unit's browser: first
  // with the core_assertion it just received, then (if the ITS ID holds more than one role) with the
  // chosen role_id, then (on later page loads) to resolve or clear its own local session cookie.
  // Credentialed (the cookie must round-trip cross-origin), so both an exact reflected Origin AND
  // allow-credentials are required - the actual trust decision (assertion signature, then session-token
  // lookup) is enforced inside each handler regardless of CORS. No other route gets this treatment.
  fastify.addHook('onRequest', (request, reply, done) => {
    const path = request.url.split('?')[0];
    const isSessionEndpoint = /^\/(v1\/)?authorization\/session(\/(me|logout|select))?$/.test(path);
    const origin = request.headers.origin;
    if (isSessionEndpoint && typeof origin === 'string') {
      void reply.header('access-control-allow-origin', origin);
      void reply.header('access-control-allow-credentials', 'true');
      void reply.header('vary', 'origin');
      if (request.method === 'OPTIONS') {
        reply
          .header('access-control-allow-methods', 'GET, POST, OPTIONS')
          .header('access-control-allow-headers', 'content-type')
          .header('access-control-max-age', '600')
          .code(204)
          .send();
        return;
      }
    }
    done();
  });

  await app.register(helmet as never, { contentSecurityPolicy: false, crossOriginEmbedderPolicy: false });
  fastify.addHook('onSend', (request, reply, _payload, done) => {
    if (!request.url.startsWith('/docs')) {
      void reply.header('content-security-policy', "default-src 'none'; frame-ancestors 'none'");
      // public keys may be cached by verifiers; everything else is no-store
      if (!request.url.startsWith('/.well-known/')) void reply.header('cache-control', 'no-store');
    }
    done();
  });

  app.enableVersioning({ type: VersioningType.URI, defaultVersion: VERSION_NEUTRAL });
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
  app.useGlobalFilters(new GlobalExceptionFilter());
  app.enableShutdownHooks();

  if (env.SWAGGER_ENABLED) {
    SwaggerModule.setup('docs', app, () => SwaggerModule.createDocument(app, buildOpenApiConfig()));
  }
  return app;
}
