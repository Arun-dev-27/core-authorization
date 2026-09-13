import { Controller, Get, HttpStatus, Inject, Res } from '@nestjs/common';
import { VERSION_NEUTRAL } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { InjectDataSource } from '@nestjs/typeorm';
import type { FastifyReply } from 'fastify';
import Redis from 'ioredis';
import { DataSource } from 'typeorm';
import { Public } from '@common/decorators/public.decorator';
import { REDIS } from '@core/cache/redis.module';

@ApiTags('health')
@Public()
@Controller({ path: 'health', version: VERSION_NEUTRAL })
export class HealthController {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    @Inject(REDIS) private readonly redis: Redis,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Liveness probe' })
  live() {
    return { status: 'ok', service: 'miqaat-core-identity-authorization-service' };
  }

  @Get('ready')
  @ApiOperation({ summary: 'Readiness probe (database + redis)' })
  async ready(@Res() reply: FastifyReply) {
    const checks = {
      database: await this.probe(() => this.db.query('SELECT 1')),
      redis: await this.probe(() => this.redis.ping()),
    };
    const ok = Object.values(checks).every((c) => c === 'up');
    void reply.status(ok ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE).send({ status: ok ? 'ready' : 'not_ready', checks });
  }

  private async probe(fn: () => Promise<unknown>): Promise<'up' | 'down'> {
    try {
      await Promise.race([fn(), new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000))]);
      return 'up';
    } catch {
      return 'down';
    }
  }
}
