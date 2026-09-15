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

  const app = await NestFactory.create<NestFastifyApplication>(AppModule, adapter, { bufferLogs: true });
  app.useLogger(new PinoNestLogger(logger));

  const fastify = app.getHttpAdapter().getInstance();
  fastify.addHook('onRequest', (request, reply, done) => {
    void reply.header('x-request-id', request.id);
    requestContext.run({ correlationId: request.id }, done);
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
