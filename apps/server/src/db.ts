import pg from 'pg';

export type Db = pg.Pool;
export type Queryable = pg.Pool | pg.PoolClient;

export function createPool(connectionString: string): Db {
  return new pg.Pool({ connectionString, max: 20 });
}

/**
 * Transaction scoped to one tenant: switches to the restricted `enclavier_app`
 * role and sets app.org_id / app.user_id so row-level security hides every
 * other organization's rows, even if a query forgets its org filter.
 */
export async function withOrgTx<T>(
  db: Db,
  scope: { orgId: string; userId: string },
  fn: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  return withTx(db, async (client) => {
    await client.query("SELECT set_config('app.org_id', $1, true), set_config('app.user_id', $2, true)", [scope.orgId, scope.userId]);
    await client.query('SET LOCAL ROLE enclavier_app');
    return fn(client);
  });
}

export async function withTx<T>(db: Db, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}
