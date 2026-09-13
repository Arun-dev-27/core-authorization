import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { QueryFailedError } from 'typeorm';
import { DomainError } from '../errors/domain-error';

interface ErrorBody {
  error: string;
  message: string;
  details?: unknown;
  correlation_id?: string;
}

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger('ExceptionFilter');

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const reply = ctx.getResponse<FastifyReply>();
    const request = ctx.getRequest<FastifyRequest>();

    const { status, body } = this.toResponse(exception);
    body.correlation_id = request?.id;

    if (status >= 500) {
      this.logger.error(exception instanceof Error ? exception : String(exception));
    }
    void reply.status(status).header('content-type', 'application/json; charset=utf-8').send(body);
  }

  private toResponse(exception: unknown): { status: number; body: ErrorBody } {
    if (exception instanceof DomainError) {
      return { status: exception.status, body: { error: exception.code, message: exception.message, details: exception.details } };
    }
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const response = exception.getResponse() as string | { message?: string | string[]; error?: string };
      if (status === HttpStatus.BAD_REQUEST && typeof response === 'object' && Array.isArray(response.message)) {
        return { status, body: { error: 'VALIDATION_ERROR', message: 'Request validation failed', details: response.message } };
      }
      const message = typeof response === 'string' ? response : (Array.isArray(response.message) ? response.message.join(', ') : response.message) ?? exception.message;
      return { status, body: { error: HttpStatus[status] ?? 'HTTP_ERROR', message } };
    }
    if (exception instanceof QueryFailedError) {
      const code = (exception as QueryFailedError & { code?: string }).code;
      if (code === '23505') {
        return { status: 409, body: { error: 'CONFLICT', message: 'Resource already exists' } };
      }
      if (code === '23503') {
        return { status: 409, body: { error: 'REFERENCE_CONFLICT', message: 'Referenced resource is missing or in use' } };
      }
      if (code === '23514') {
        return { status: 400, body: { error: 'CONSTRAINT_VIOLATION', message: 'Value violates a database constraint' } };
      }
    }
    return { status: 500, body: { error: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } };
  }
}
