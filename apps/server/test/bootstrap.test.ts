import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createAccount } from '@enclavier/crypto';
import type { Db } from '../src/db';
import { DATABASE_URL, FAST_KDF, resetDb, setupApp } from './helpers';

describe.skipIf(!DATABASE_URL)('Fresh install with sign-ups closed (integration)', () => {
  let app: FastifyInstance;
  let db: Db;

  const register = async (email: string) => {
    const { payload } = await createAccount(`${email}-master-password`, FAST_KDF);
    return app.inject({ method: 'POST', url: '/api/auth/register', payload: { ...payload, email, name: 'Admin' } });
  };
  const info = async () => (await app.inject({ method: 'GET', url: '/api/server-info' })).json();

  beforeAll(async () => {
    db = await resetDb();
    ({ app } = await setupApp(db, { SIGNUPS_ENABLED: 'false' }));
  });

  afterAll(async () => {
    await app?.close();
    await db?.end();
  });

  it('reports that setup is required', async () => {
    expect(await info()).toMatchObject({ name: 'Enclavier', setupRequired: true, signupsEnabled: true });
  });

  it('lets exactly one first account register, even under a race', async () => {
    const results = await Promise.all([register('first@corp.test'), register('second@corp.test'), register('third@corp.test')]);
    const codes = results.map((r) => r.statusCode).sort();
    expect(codes).toEqual([201, 403, 403]);
    expect((await db.query('SELECT count(*)::int AS n FROM users')).rows[0].n).toBe(1);
  });

  it('closes sign-up afterwards', async () => {
    expect((await register('late@corp.test')).statusCode).toBe(403);
    expect(await info()).toMatchObject({ setupRequired: false, signupsEnabled: false });
  });
});
