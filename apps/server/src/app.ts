import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import type { Config } from './config';
import type { Db } from './db';
import { HttpError, unauthorized } from './errors';
import { PurposeTokens, SecretBox, TokenService } from './security';
import { authRoutes, isFreshInstall } from './routes/auth';
import { accountRoutes } from './routes/account';
import { vaultRoutes } from './routes/vault';
import { orgRoutes } from './routes/orgs';
import { twoFactorRoutes } from './routes/twofactor';
import { emergencyRoutes } from './routes/emergency';
import { orgRecoveryRoutes } from './routes/orgRecovery';
import { monitoringRoutes } from './routes/monitoring';
import { breachRoutes } from './routes/breach';
import { ssoRoutes } from './routes/sso';
import { ssoAdminRoutes } from './routes/ssoAdmin';
import { deviceRoutes } from './routes/devices';
import { scimRoutes } from './routes/scim';
import { resolveTxt } from 'node:dns/promises';
import { createMailer, type Mailer } from './mail';

export interface AuthContext {
  userId: string;
  sessionId: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    auth: AuthContext | null;
  }
  interface FastifyInstance {
    config: Config;
    db: Db;
    tokens: TokenService;
    mailer: Mailer;
    secrets: SecretBox;
    purposeTokens: PurposeTokens;
    authenticate: (req: FastifyRequest) => Promise<void>;
    resolveTxt: (name: string) => Promise<string[][]>;
  }
}

export function requireAuth(req: FastifyRequest): AuthContext {
  if (!req.auth) throw unauthorized();
  return req.auth;
}

export interface AppDeps {
  mailer?: Mailer;
  /** DNS TXT lookups for domain verification (replaced in tests). */
  resolveTxt?: (name: string) => Promise<string[][]>;
}

export async function buildApp(config: Config, db: Db, deps: AppDeps = {}): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      // Never log bodies or auth headers: they carry key material and tokens.
      redact: ['req.headers.authorization', 'req.headers.cookie'],
    },
    trustProxy: config.TRUST_PROXY,
    bodyLimit: 5 * 1024 * 1024,
  });

  app.decorate('config', config);
  app.decorate('db', db);
  app.decorate('tokens', new TokenService(config.JWT_SECRET, config.ACCESS_TOKEN_TTL_SECONDS));
  app.decorate('mailer', deps.mailer ?? createMailer(config, app.log));
  app.decorate('secrets', new SecretBox(config.SERVER_SECRET));
  app.decorate('purposeTokens', new PurposeTokens(config.JWT_SECRET));
  app.decorate('resolveTxt', deps.resolveTxt ?? resolveTxt);
  app.decorateRequest('auth', null);

  await app.register(helmet, {
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    hsts: { maxAge: 31536000, includeSubDomains: true },
  });
  await app.register(rateLimit, { global: false });

  app.decorate('authenticate', async (req: FastifyRequest) => {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) throw unauthorized();
    let claims;
    try {
      claims = await app.tokens.verify(header.slice(7));
    } catch {
      throw unauthorized('Invalid or expired token');
    }
    // Sessions are checked on every request so revocation is immediate.
    const { rowCount } = await db.query(
      'SELECT 1 FROM sessions WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()',
      [claims.sid, claims.sub],
    );
    if (!rowCount) throw unauthorized('Session revoked');
    req.auth = { userId: claims.sub, sessionId: claims.sid };
  });

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof HttpError) {
      return reply.status(err.statusCode).send({ error: err.code, message: err.message });
    }
    // Constraint violations are client errors (duplicate ids, references to
    // collections/groups/members outside the caller's organization).
    const pgCode = (err as { code?: string }).code;
    if (pgCode === '23505') return reply.status(409).send({ error: 'conflict', message: 'A record with this id already exists' });
    if (pgCode === '23503') return reply.status(400).send({ error: 'bad_request', message: 'Request references an unknown collection, group or member' });
    const { statusCode: status, message } = err as { statusCode?: number; message?: string };
    if (status && status < 500) {
      return reply.status(status).send({ error: 'request_error', message: message ?? 'Bad request' });
    }
    req.log.error(err);
    return reply.status(500).send({ error: 'internal', message: 'Internal server error' });
  });

  app.get('/health', async () => {
    await db.query('SELECT 1');
    return { status: 'ok' };
  });

  /** Public, non-sensitive facts the clients need before anyone is signed in. */
  app.get('/api/server-info', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async () => {
    const fresh = await isFreshInstall(db);
    return {
      name: 'Enclavier',
      version: process.env.ENCLAVIER_VERSION ?? 'dev',
      // Sign-up is possible when open, or for the first account of a new install.
      signupsEnabled: config.SIGNUPS_ENABLED || fresh,
      setupRequired: fresh,
    };
  });

  await app.register(authRoutes, { prefix: '/api/auth' });
  await app.register(accountRoutes, { prefix: '/api/account' });
  await app.register(vaultRoutes, { prefix: '/api' });
  await app.register(orgRoutes, { prefix: '/api' });
  await app.register(twoFactorRoutes, { prefix: '/api/account/2fa' });
  await app.register(emergencyRoutes, { prefix: '/api/emergency' });
  await app.register(orgRecoveryRoutes, { prefix: '/api' });
  await app.register(monitoringRoutes, { prefix: '/api' });
  await app.register(breachRoutes, { prefix: '/api/breach' });
  await app.register(ssoRoutes, { prefix: '/api/sso' });
  await app.register(ssoAdminRoutes, { prefix: '/api' });
  await app.register(deviceRoutes, { prefix: '/api' });
  await app.register(scimRoutes, { prefix: '/api/scim/v2' });

  return app;
}
