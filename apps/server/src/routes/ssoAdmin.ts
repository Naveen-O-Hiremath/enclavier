import { randomBytes, randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  domainCreate,
  scimTokenCreate,
  ssoConfigUpdate,
  type OrgDomain,
  type ScimToken,
  type SsoAdminView,
} from '@enclavier/shared';
import { requireAuth } from '../app';
import { recordAudit, type AuditInput } from '../audit';
import { withOrgTx, type Queryable } from '../db';
import { badRequest, conflict, notFound, parse } from '../errors';
import { requireAdmin, requireOwner } from '../orgs/access';
import { sha256 } from '../security';
import { oidcConfiguration, SsoError } from '../sso/protocols';
import { loadSsoConfig, maskSettings, serviceProvider } from '../sso/store';

const orgParam = z.object({ orgId: z.string().uuid() });
const idParam = orgParam.extend({ id: z.string().uuid() });

export const TXT_PREFIX = '_enclavier';
const txtValue = (token: string) => `enclavier-domain-verification=${token}`;

interface DomainRow {
  id: string;
  domain: string;
  verification_token: string;
  verified_at: Date | null;
  last_checked_at: Date | null;
}

function toDomain(r: DomainRow): OrgDomain {
  return {
    id: r.id,
    domain: r.domain,
    verified: !!r.verified_at,
    verifiedAt: r.verified_at?.toISOString() ?? null,
    lastCheckedAt: r.last_checked_at?.toISOString() ?? null,
    record: { name: `${TXT_PREFIX}.${r.domain}`, value: txtValue(r.verification_token) },
  };
}

export async function ssoAdminRoutes(app: FastifyInstance): Promise<void> {
  const { db, config, secrets } = app;
  app.addHook('preHandler', app.authenticate);

  const audit = (client: Queryable, req: FastifyRequest, orgId: string, input: Omit<AuditInput, 'userId' | 'orgId'>) =>
    recordAudit(client, req, { ...input, orgId, userId: req.auth?.userId ?? null });

  // ---- SSO configuration -------------------------------------------------------------------

  app.get('/orgs/:orgId/sso', async (req): Promise<SsoAdminView> => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    return withOrgTx(db, { orgId, userId }, async (client) => {
      await requireAdmin(client, orgId, userId);
      const cfg = await loadSsoConfig(client, secrets, orgId);
      const domains = await client.query<DomainRow>('SELECT * FROM org_domains WHERE org_id = $1 ORDER BY domain', [orgId]);
      return {
        config: cfg
          ? {
              enabled: cfg.enabled,
              identifier: cfg.identifier,
              jitProvisioning: cfg.jitProvisioning,
              enforce: cfg.enforce,
              groupSync: cfg.groupSync,
              settings: maskSettings(cfg.settings),
            }
          : null,
        serviceProvider: serviceProvider(config, orgId),
        domains: domains.rows.map(toDomain),
        scimBaseUrl: `${config.PUBLIC_URL.replace(/\/$/, '')}/api/scim/v2`,
      };
    });
  });

  app.put('/orgs/:orgId/sso', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req) => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    const body = parse(ssoConfigUpdate, req.body);
    // Only owners can change how everyone signs in.
    await withOrgTx(db, { orgId, userId }, (client) => requireOwner(client, orgId, userId));
    const current = await loadSsoConfig(db, secrets, orgId);
    const settings = { ...body.settings };
    if (settings.type === 'oidc') {
      const keep = !settings.clientSecret || settings.clientSecret.startsWith('••••');
      const previous = current?.settings.type === 'oidc' ? current.settings.clientSecret : undefined;
      settings.clientSecret = keep ? previous : settings.clientSecret;
      if (body.enabled) {
        // Fail now, with a useful message, rather than at the first sign-in.
        try {
          await oidcConfiguration(app, settings);
        } catch (err) {
          if (err instanceof SsoError) throw badRequest(err.message);
          throw err;
        }
      }
    }
    await withOrgTx(db, { orgId, userId }, async (client) => {
      const taken = await client.query('SELECT 1 FROM sso_configs WHERE identifier = $1 AND org_id <> $2', [body.identifier, orgId]);
      // RLS hides other tenants' rows, so rely on the unique index for them (caught below).
      if (taken.rowCount) throw conflict('This identifier is already in use');
      try {
        await client.query(
          `INSERT INTO sso_configs (org_id, enabled, identifier, type, settings_enc, jit_provisioning, enforce, group_sync, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
           ON CONFLICT (org_id) DO UPDATE SET enabled = EXCLUDED.enabled, identifier = EXCLUDED.identifier, type = EXCLUDED.type,
             settings_enc = EXCLUDED.settings_enc, jit_provisioning = EXCLUDED.jit_provisioning, enforce = EXCLUDED.enforce,
             group_sync = EXCLUDED.group_sync, updated_at = now()`,
          [orgId, body.enabled, body.identifier, settings.type, secrets.seal(JSON.stringify(settings)), body.jitProvisioning, body.enforce, body.groupSync],
        );
      } catch (err) {
        if ((err as { code?: string }).code === '23505') throw conflict('This identifier is already in use by another organization');
        throw err;
      }
      await audit(client, req, orgId, {
        action: 'org.sso_updated',
        targetType: 'org',
        targetId: orgId,
        metadata: { type: settings.type, enabled: body.enabled, enforce: body.enforce, jitProvisioning: body.jitProvisioning, groupSync: body.groupSync },
      });
    });
    return { ok: true };
  });

  // ---- domain verification -------------------------------------------------------------------

  app.post('/orgs/:orgId/domains', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    const { domain } = parse(domainCreate, req.body);
    const row = await withOrgTx(db, { orgId, userId }, async (client) => {
      await requireOwner(client, orgId, userId);
      const { rows } = await client.query<DomainRow>(
        `INSERT INTO org_domains (id, org_id, domain, verification_token) VALUES ($1, $2, $3, $4)
         ON CONFLICT (org_id, domain) DO NOTHING RETURNING *`,
        [randomUUID(), orgId, domain, randomBytes(24).toString('base64url')],
      );
      if (!rows[0]) throw conflict('This domain was already added');
      await audit(client, req, orgId, { action: 'org.domain_added', targetType: 'domain', targetId: rows[0].id, metadata: { domain } });
      return rows[0];
    });
    return reply.status(201).send(toDomain(row));
  });

  app.post('/orgs/:orgId/domains/:id/verify', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req): Promise<OrgDomain> => {
    const { userId } = requireAuth(req);
    const { orgId, id } = parse(idParam, req.params);
    const row = await withOrgTx(db, { orgId, userId }, async (client) => {
      await requireOwner(client, orgId, userId);
      const { rows } = await client.query<DomainRow>('SELECT * FROM org_domains WHERE org_id = $1 AND id = $2', [orgId, id]);
      if (!rows[0]) throw notFound('Domain not found');
      return rows[0];
    });
    if (row.verified_at) return toDomain(row);
    let records: string[][] = [];
    try {
      records = await app.resolveTxt(`${TXT_PREFIX}.${row.domain}`);
    } catch {
      records = [];
    }
    const found = records.some((chunks) => chunks.join('') === txtValue(row.verification_token));
    return withOrgTx(db, { orgId, userId }, async (client) => {
      if (!found) {
        // Not an error: the client shows "not found yet" (DNS changes can take a while to appear).
        const checked = await client.query<DomainRow>('UPDATE org_domains SET last_checked_at = now() WHERE id = $1 RETURNING *', [id]);
        return toDomain(checked.rows[0]!);
      }
      let updated;
      try {
        updated = await client.query<DomainRow>('UPDATE org_domains SET verified_at = now(), last_checked_at = now() WHERE id = $1 RETURNING *', [id]);
      } catch (err) {
        if ((err as { code?: string }).code === '23505') throw conflict('Another organization has already verified this domain');
        throw err;
      }
      await audit(client, req, orgId, { action: 'org.domain_verified', targetType: 'domain', targetId: id, metadata: { domain: row.domain } });
      return toDomain(updated.rows[0]!);
    });
  });

  app.delete('/orgs/:orgId/domains/:id', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { orgId, id } = parse(idParam, req.params);
    await withOrgTx(db, { orgId, userId }, async (client) => {
      await requireOwner(client, orgId, userId);
      const { rows } = await client.query<{ domain: string }>('DELETE FROM org_domains WHERE org_id = $1 AND id = $2 RETURNING domain', [orgId, id]);
      if (!rows[0]) throw notFound('Domain not found');
      await audit(client, req, orgId, { action: 'org.domain_removed', targetType: 'domain', targetId: id, metadata: { domain: rows[0].domain } });
    });
    return reply.status(204).send();
  });

  // ---- SCIM tokens ---------------------------------------------------------------------------

  app.get('/orgs/:orgId/scim-tokens', async (req): Promise<ScimToken[]> => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    return withOrgTx(db, { orgId, userId }, async (client) => {
      await requireAdmin(client, orgId, userId);
      const { rows } = await client.query('SELECT id, name, created_at, last_used_at FROM scim_tokens WHERE org_id = $1 ORDER BY created_at', [orgId]);
      return rows.map((r) => ({ id: r.id, name: r.name, createdAt: r.created_at.toISOString(), lastUsedAt: r.last_used_at?.toISOString() ?? null }));
    });
  });

  app.post('/orgs/:orgId/scim-tokens', async (req, reply): Promise<ScimToken> => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    const { name } = parse(scimTokenCreate, req.body);
    const token = `enc_scim_${randomBytes(32).toString('base64url')}`;
    const id = randomUUID();
    const created = await withOrgTx(db, { orgId, userId }, async (client) => {
      await requireOwner(client, orgId, userId);
      const { rows } = await client.query<{ created_at: Date }>(
        'INSERT INTO scim_tokens (id, org_id, name, token_hash, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING created_at',
        [id, orgId, name, sha256(token), userId],
      );
      await audit(client, req, orgId, { action: 'org.scim_token_created', targetType: 'scim_token', targetId: id, metadata: { name } });
      return rows[0]!;
    });
    return reply.status(201).send({ id, name, createdAt: created.created_at.toISOString(), lastUsedAt: null, token });
  });

  app.delete('/orgs/:orgId/scim-tokens/:id', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { orgId, id } = parse(idParam, req.params);
    await withOrgTx(db, { orgId, userId }, async (client) => {
      await requireOwner(client, orgId, userId);
      const res = await client.query('DELETE FROM scim_tokens WHERE org_id = $1 AND id = $2', [orgId, id]);
      if (!res.rowCount) throw notFound('Token not found');
      await audit(client, req, orgId, { action: 'org.scim_token_revoked', targetType: 'scim_token', targetId: id });
    });
    return reply.status(204).send();
  });
}
