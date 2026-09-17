import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { ADMIN_DB_ENTITIES } from './entities';

/**
 * Refuses to boot unless AUTHZ_DB_* points at an existing database whose AUTHZ_DB_SCHEMA already holds every table
 * and column the entities map. Read-only: it queries information_schema and never creates or alters anything.
 */
@Injectable()
export class AdminSchemaCheck implements OnModuleInit {
  private readonly logger = new Logger(AdminSchemaCheck.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly config: AppConfig,
  ) {}

  async onModuleInit(): Promise<void> {
    const schema = this.config.env.AUTHZ_DB_SCHEMA;
    const rows = (await this.db.query(
      `SELECT c.table_name, c.column_name
         FROM information_schema.columns c
         JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
        WHERE c.table_schema = $1`,
      [schema],
    )) as { table_name: string; column_name: string }[];

    const columnsByTable = new Map<string, Set<string>>();
    for (const r of rows) {
      if (!columnsByTable.has(r.table_name)) columnsByTable.set(r.table_name, new Set());
      columnsByTable.get(r.table_name)!.add(r.column_name);
    }

    const problems: string[] = [];
    if (columnsByTable.size === 0) problems.push(`schema "${schema}" does not exist or has no tables`);
    else {
      for (const entity of ADMIN_DB_ENTITIES) {
        const metadata = this.db.getMetadata(entity);
        const present = columnsByTable.get(metadata.tableName);
        if (!present) {
          problems.push(`table ${schema}.${metadata.tableName} is missing`);
          continue;
        }
        for (const column of metadata.columns) {
          if (!present.has(column.databaseName)) problems.push(`column ${schema}.${metadata.tableName}.${column.databaseName} is missing`);
        }
      }
    }
    if (problems.length) throw new Error(`authorization database is not the expected existing database: ${problems.join('; ')}`);
    this.logger.log({ msg: 'existing authorization schema verified', database: this.config.env.AUTHZ_DB_NAME, schema });
  }
}
