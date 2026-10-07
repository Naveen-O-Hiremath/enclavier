import type { FastifyInstance } from 'fastify';
import { createAccount, type KdfParams, type UnlockedKeys } from '@enclavier/crypto';
import { buildApp, type AppDeps } from '../src/app';
import { loadConfig, type Config } from '../src/config';
import { createPool, type Db } from '../src/db';
import type { MailMessage } from '../src/mail';
import { migrate } from '../src/migrations';

export const DATABASE_URL = process.env.TEST_DATABASE_URL;
export const FAST_KDF: KdfParams = { algorithm: 'argon2id', memory: 19 * 1024, iterations: 2, parallelism: 1 };

export function testConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig({
    DATABASE_URL: DATABASE_URL!,
    JWT_SECRET: 'test-jwt-secret-test-jwt-secret-test',
    SERVER_SECRET: 'test-server-secret-test-server-secret',
    LOG_LEVEL: 'silent',
    PUBLIC_URL: 'https://vault.example.test',
    ...overrides,
  });
}

/** Fresh schema per test file (files run sequentially, see vitest.config.ts). */
export async function resetDb(): Promise<Db> {
  const db = createPool(DATABASE_URL!);
  await db.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
  await migrate(db);
  return db;
}

export async function setupApp(db: Db, overrides: Record<string, string> = {}, deps: Omit<AppDeps, 'mailer'> = {}) {
  const outbox: MailMessage[] = [];
  const app = await buildApp(testConfig(overrides), db, {
    ...deps,
    mailer: { send: async (m) => void outbox.push(m) },
  });
  return { app, outbox };
}

export interface TestUser {
  id: string;
  email: string;
  keys: UnlockedKeys;
  access: string;
  auth: { authorization: string };
}

export async function registerUser(app: FastifyInstance, email: string, password = `${email}-master-password`, extra: object = {}): Promise<TestUser> {
  const { payload, keys } = await createAccount(password, FAST_KDF);
  const res = await app.inject({
    method: 'POST',
    url: '/api/auth/register',
    payload: { ...payload, email, name: email.split('@')[0], ...extra },
  });
  if (res.statusCode !== 201) throw new Error(`register ${email}: ${res.statusCode} ${res.body}`);
  const body = res.json();
  return { id: body.profile.id, email, keys, access: body.accessToken, auth: { authorization: `Bearer ${body.accessToken}` } };
}
