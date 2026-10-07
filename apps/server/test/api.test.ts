import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  createAccount,
  decryptItem,
  deriveLoginSecrets,
  encryptItem,
  fromB64,
  rewrapUserKey,
  unlockAccount,
  updateItem,
  uuid,
} from '@enclavier/crypto';
import { verifyAuditChain } from '../src/audit';
import type { Db } from '../src/db';
import { DATABASE_URL, FAST_KDF, resetDb, setupApp } from './helpers';

describe.skipIf(!DATABASE_URL)('API (integration, requires TEST_DATABASE_URL)', () => {
  let app: FastifyInstance;
  let db: Db;

  beforeAll(async () => {
    db = await resetDb();
    ({ app } = await setupApp(db));
  });

  afterAll(async () => {
    await app?.close();
    await db?.end();
  });

  const email = 'alice@example.com';
  const password = 'correct horse battery staple';
  let access = '';
  let refresh = '';

  const auth = () => ({ authorization: `Bearer ${access}` });

  it('registers without ever sending the password', async () => {
    const { payload } = await createAccount(password, FAST_KDF);
    const res = await app.inject({ method: 'POST', url: '/api/auth/register', payload: { ...payload, email, name: 'Alice' } });
    expect(res.statusCode).toBe(201);
    expect(res.body).not.toContain(password);
    const { rows } = await db.query('SELECT auth_hash FROM users WHERE email = $1', [email]);
    expect(rows[0].auth_hash).toMatch(/^scrypt\$/);
    expect(rows[0].auth_hash).not.toContain(payload.authHash);
  });

  it('rejects duplicate registration', async () => {
    const { payload } = await createAccount(password, FAST_KDF);
    const res = await app.inject({ method: 'POST', url: '/api/auth/register', payload: { ...payload, email, name: 'Mallory' } });
    expect(res.statusCode).toBe(409);
  });

  it('prelogin returns stable fake params for unknown e-mails', async () => {
    const a = await app.inject({ method: 'POST', url: '/api/auth/prelogin', payload: { email: 'ghost@example.com' } });
    const b = await app.inject({ method: 'POST', url: '/api/auth/prelogin', payload: { email: 'ghost@example.com' } });
    expect(a.statusCode).toBe(200);
    expect(a.json()).toEqual(b.json());
    expect(fromB64(a.json().salt)).toHaveLength(16);
  });

  it('logs in with the derived auth hash and unlocks locally', async () => {
    const pre = (await app.inject({ method: 'POST', url: '/api/auth/prelogin', payload: { email } })).json();
    const { authHash } = await deriveLoginSecrets(password, fromB64(pre.salt), pre.kdf);

    const bad = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email, authHash: 'A'.repeat(43) } });
    expect(bad.statusCode).toBe(401);

    const res = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email, authHash, deviceName: 'test' } });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    access = body.accessToken;
    refresh = body.refreshToken;
    await expect(unlockAccount(password, body.keys)).resolves.toBeDefined();
  });

  it('stores only ciphertext and enforces optimistic concurrency', async () => {
    const me = (await app.inject({ method: 'GET', url: '/api/account/me', headers: auth() })).json();
    const keys = await unlockAccount(password, me.keys);
    const id = uuid();
    const secret = { type: 'login', name: 'GitHub', login: { username: 'alice', password: 'hunter2-very-secret' } };

    const created = await app.inject({ method: 'POST', url: '/api/items', headers: auth(), payload: encryptItem(keys.userKey, id, null, secret) });
    expect(created.statusCode).toBe(201);
    const raw = await db.query('SELECT key, data FROM items WHERE id = $1', [id]);
    expect(JSON.stringify(raw.rows)).not.toContain('hunter2');

    const item = created.json();
    const data = updateItem(keys.userKey, item, { ...secret, name: 'GitHub (work)' });
    const ok = await app.inject({ method: 'PUT', url: `/api/items/${id}`, headers: auth(), payload: { folderId: null, data, revision: 1 } });
    expect(ok.statusCode).toBe(200);
    const stale = await app.inject({ method: 'PUT', url: `/api/items/${id}`, headers: auth(), payload: { folderId: null, data, revision: 1 } });
    expect(stale.statusCode).toBe(409);

    const sync = (await app.inject({ method: 'GET', url: '/api/sync', headers: auth() })).json();
    expect(decryptItem<typeof secret>(keys.userKey, sync.items[0]).name).toBe('GitHub (work)');
  });

  it('isolates users from each other', async () => {
    const { payload } = await createAccount('bob password 12345', FAST_KDF);
    const reg = (await app.inject({ method: 'POST', url: '/api/auth/register', payload: { ...payload, email: 'bob@example.com', name: 'Bob' } })).json();
    const bobSync = (await app.inject({ method: 'GET', url: '/api/sync', headers: { authorization: `Bearer ${reg.accessToken}` } })).json();
    expect(bobSync.items).toHaveLength(0);
    const aliceItemId = (await db.query("SELECT id FROM items LIMIT 1")).rows[0].id;
    const steal = await app.inject({ method: 'DELETE', url: `/api/items/${aliceItemId}`, headers: { authorization: `Bearer ${reg.accessToken}` } });
    expect(steal.statusCode).toBe(404);
  });

  it('rotates refresh tokens and revokes the session on reuse', async () => {
    const first = await app.inject({ method: 'POST', url: '/api/auth/refresh', payload: { refreshToken: refresh } });
    expect(first.statusCode).toBe(200);
    const rotated = first.json();

    const replay = await app.inject({ method: 'POST', url: '/api/auth/refresh', payload: { refreshToken: refresh } });
    expect(replay.statusCode).toBe(401);
    // The legitimate holder is now logged out too: the token family is burned.
    const after = await app.inject({ method: 'GET', url: '/api/sync', headers: { authorization: `Bearer ${rotated.accessToken}` } });
    expect(after.statusCode).toBe(401);
  });

  it('changes the master password without re-encrypting the vault', async () => {
    const pre = (await app.inject({ method: 'POST', url: '/api/auth/prelogin', payload: { email } })).json();
    const { authHash } = await deriveLoginSecrets(password, fromB64(pre.salt), pre.kdf);
    const login = (await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email, authHash } })).json();
    access = login.accessToken;

    const keys = await unlockAccount(password, login.keys);
    const change = await rewrapUserKey(keys, 'a brand new master password', FAST_KDF);
    const res = await app.inject({ method: 'POST', url: '/api/account/password', headers: auth(), payload: { ...change, currentAuthHash: authHash } });
    expect(res.statusCode).toBe(204);

    const oldLogin = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email, authHash } });
    expect(oldLogin.statusCode).toBe(401);
    const sync = (await app.inject({ method: 'GET', url: '/api/sync', headers: auth() })).json();
    const newKeys = await unlockAccount('a brand new master password', sync.keys);
    expect(decryptItem<{ name: string }>(newKeys.userKey, sync.items[0]).name).toBe('GitHub (work)');
  });

  it('keeps an intact, append-only audit chain', async () => {
    const result = await verifyAuditChain(db);
    expect(result.ok).toBe(true);
    expect(result.checked).toBeGreaterThan(5);
    await expect(db.query("UPDATE audit_events SET action = 'x' WHERE id = 1")).rejects.toThrow(/append-only/);
    await expect(db.query('DELETE FROM audit_events')).rejects.toThrow(/append-only/);
  });
});
