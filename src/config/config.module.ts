import { Global, Module } from '@nestjs/common';
import { Env, loadEnv } from './configuration';

export class AppConfig {
  constructor(readonly env: Env) {}

  get isProduction(): boolean {
    return this.env.NODE_ENV === 'production';
  }
}

@Global()
@Module({
  providers: [{ provide: AppConfig, useFactory: () => new AppConfig(loadEnv()) }],
  exports: [AppConfig],
})
export class ConfigModule {}
