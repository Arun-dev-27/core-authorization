import type { DataSource, EntityManager } from 'typeorm';

export type Queryable = DataSource | EntityManager;

export async function queryOne<T>(db: Queryable, sql: string, params: unknown[] = []): Promise<T | null> {
  const rows = (await db.query(sql, params)) as T[];
  return rows[0] ?? null;
}

export async function queryMany<T>(db: Queryable, sql: string, params: unknown[] = []): Promise<T[]> {
  return (await db.query(sql, params)) as T[];
}

/** Postgres returns [rows, affectedCount] for UPDATE/DELETE ... RETURNING through TypeORM. */
export function returningRows<T>(result: unknown): T[] {
  if (Array.isArray(result) && result.length === 2 && Array.isArray(result[0]) && typeof result[1] === 'number') {
    return result[0] as T[];
  }
  return result as T[];
}
