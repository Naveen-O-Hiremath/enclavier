import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { BreachedAccount } from '@enclavier/shared';
import { requireAuth } from '../app';
import { HttpError, parse } from '../errors';
import { findUser } from '../users';

const prefixParam = z.object({ prefix: z.string().regex(/^[0-9A-Fa-f]{5}$/) });
const RANGE_TTL_MS = 24 * 3600_000;
const MAX_CACHE = 5000;

/**
 * Breach monitoring via Have I Been Pwned.
 *
 * Passwords use k-anonymity: the browser hashes the password with SHA-1 and
 * asks for the 5-hex-character prefix only; matching the suffix happens in the
 * browser. The server proxies (keeping the strict CSP) and never sees a
 * password or full hash. HIBP_API_URL can point at an offline mirror.
 */
export async function breachRoutes(app: FastifyInstance): Promise<void> {
  const { config } = app;
  const cache = new Map<string, { body: string; expires: number }>();
  app.addHook('preHandler', app.authenticate);

  const passwordsEnabled = () => !!config.HIBP_API_URL;
  const accountsEnabled = () => !!config.HIBP_API_KEY;

  app.get('/status', async () => ({ passwords: passwordsEnabled(), accounts: accountsEnabled() }));

  app.get('/range/:prefix', { config: { rateLimit: { max: 600, timeWindow: '1 minute' } } }, async (req, reply) => {
    const prefix = parse(prefixParam, req.params).prefix.toUpperCase();
    if (!passwordsEnabled()) throw new HttpError(503, 'disabled', 'Breach checks are disabled on this server');
    const hit = cache.get(prefix);
    let body = hit && hit.expires > Date.now() ? hit.body : null;
    if (!body) {
      let res: Response;
      try {
        res = await fetch(`${config.HIBP_API_URL.replace(/\/$/, '')}/range/${prefix}`, {
          headers: { 'add-padding': 'true', 'user-agent': 'Enclavier-Password-Manager' },
          signal: AbortSignal.timeout(10_000),
        });
      } catch {
        throw new HttpError(502, 'upstream', 'Breach database is unreachable');
      }
      if (!res.ok) throw new HttpError(502, 'upstream', `Breach database responded ${res.status}`);
      body = await res.text();
      if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value!);
      cache.set(prefix, { body, expires: Date.now() + RANGE_TTL_MS });
    }
    reply.type('text/plain').header('cache-control', 'private, max-age=3600');
    return body;
  });

  /** Breaches containing the signed-in user's own e-mail address (never an arbitrary address). */
  app.get('/account', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req): Promise<BreachedAccount[]> => {
    if (!accountsEnabled()) throw new HttpError(404, 'not_configured', 'Account breach monitoring requires HIBP_API_KEY');
    const user = await findUser(app.db, 'id', requireAuth(req).userId);
    if (!user) throw new HttpError(401, 'unauthorized', 'Authentication required');
    const res = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(user.email)}?truncateResponse=false`, {
      headers: { 'hibp-api-key': config.HIBP_API_KEY!, 'user-agent': 'Enclavier-Password-Manager' },
      signal: AbortSignal.timeout(10_000),
    }).catch(() => {
      throw new HttpError(502, 'upstream', 'Breach database is unreachable');
    });
    if (res.status === 404) return [];
    if (!res.ok) throw new HttpError(502, 'upstream', `Breach database responded ${res.status}`);
    const rows = (await res.json()) as { Name: string; Domain: string; BreachDate: string; DataClasses: string[] }[];
    return rows.map((b) => ({ name: b.Name, domain: b.Domain, breachDate: b.BreachDate, dataClasses: b.DataClasses }));
  });
}
