import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { LoggerService } from '@nestjs/common';
import { Logger } from 'pino';
import pino from 'pino';
import { currentCorrelationId } from './request-context';

/** Paths that must never reach log sinks. */
export const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-api-key"]',
  'res.headers["set-cookie"]',
  '*.password',
  '*.api_key',
  '*.key_hash',
];

export function createLogger(level: string): Logger {
  return pino({
    level,
    base: { service: 'miqaat-core-identity-authorization-service' },
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]{8,128}$/;

/** Accepts a well-formed inbound X-Request-ID for cross-service correlation, otherwise generates one. */
export function genRequestId(req: IncomingMessage): string {
  const inbound = req.headers['x-request-id'];
  return typeof inbound === 'string' && REQUEST_ID_PATTERN.test(inbound) ? inbound : randomUUID();
}

/** Routes Nest's Logger through pino and stamps the request correlation id. */
export class PinoNestLogger implements LoggerService {
  constructor(private readonly logger: Logger) {}

  private write(level: 'info' | 'error' | 'warn' | 'debug' | 'trace', message: unknown, context?: string, extra?: object) {
    const correlation_id = currentCorrelationId();
    const payload = { context, correlation_id, ...extra };
    if (message instanceof Error) {
      this.logger[level]({ ...payload, err: message }, message.message);
    } else if (typeof message === 'object' && message !== null) {
      this.logger[level]({ ...payload, ...message });
    } else {
      this.logger[level](payload, String(message));
    }
  }

  log(message: unknown, context?: string) {
    this.write('info', message, context);
  }
  error(message: unknown, stackOrContext?: string, context?: string) {
    this.write('error', message, context ?? stackOrContext, context ? { stack: stackOrContext } : undefined);
  }
  warn(message: unknown, context?: string) {
    this.write('warn', message, context);
  }
  debug(message: unknown, context?: string) {
    this.write('debug', message, context);
  }
  verbose(message: unknown, context?: string) {
    this.write('trace', message, context);
  }
}
