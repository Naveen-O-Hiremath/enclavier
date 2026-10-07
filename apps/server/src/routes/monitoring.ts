import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  auditQuery,
  destinationCreate,
  destinationUpdate,
  type AuditVerifyResult,
  type ComplianceReport,
  type LogDestination,
  type OrgEvent,
} from '@enclavier/shared';
import { requireAuth } from '../app';
import { recordAudit, verifyOrgChain } from '../audit';
import { withOrgTx, type Queryable } from '../db';
import { badRequest, notFound, parse } from '../errors';
import { loadPolicies, requireAdmin } from '../orgs/access';
import { deliver, destinationConfig, DestinationError, redact, SECRET_FIELDS, type DestinationConfig, type StreamEvent } from '../siem/destinations';
import { buildComplianceReport } from '../compliance';
import { policiesToDto } from './orgRecovery';

const orgParam = z.object({ orgId: z.string().uuid() });
const destParam = orgParam.extend({ destId: z.string().uuid() });
const exportQuery = auditQuery.omit({ before: true, limit: true }).extend({ format: z.enum(['csv', 'ndjson']).default('csv') });

interface EventRow {
  id: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  user_agent: string | null;
  metadata: Record<string, unknown>;
  created_at: Date;
  actor_email: string | null;
  org_seq: string | null;
  org_hash: Buffer | null;
}

const toEvent = (r: EventRow): OrgEvent => ({
  id: Number(r.id),
  action: r.action,
  actorEmail: r.actor_email,
  targetType: r.target_type,
  targetId: r.target_id,
  ip: r.ip,
  userAgent: r.user_agent,
  metadata: r.metadata,
  createdAt: r.created_at.toISOString(),
  orgSeq: r.org_seq ? Number(r.org_seq) : null,
});

/** Filtered query over one org's audit events (newest first). */
function eventQuery(orgId: string, q: { action?: string; actor?: string; from?: string; to?: string; before?: number }, limit: number) {
  return {
    text: `SELECT e.id, e.action, e.target_type, e.target_id, e.ip, e.user_agent, e.metadata, e.created_at, e.org_seq, e.org_hash,
                  u.email AS actor_email
             FROM audit_events e LEFT JOIN users u ON u.id = e.user_id
            WHERE e.org_id = $1
              AND ($2::text IS NULL OR e.action LIKE $2 || '%')
              AND ($3::text IS NULL OR u.email ILIKE '%' || $3 || '%')
              AND ($4::timestamptz IS NULL OR e.created_at >= $4)
              AND ($5::timestamptz IS NULL OR e.created_at <= $5)
              AND ($6::bigint IS NULL OR e.id < $6)
            ORDER BY e.id DESC LIMIT $7`,
    values: [orgId, q.action || null, q.actor || null, q.from ?? null, q.to ?? null, q.before ?? null, limit],
  };
}

const csvCell = (v: unknown) => {
  const s = v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
  // Quote everything and neutralise spreadsheet formulas (CSV injection).
  return `"${(/^[=+\-@\t\r]/.test(s) ? `'${s}` : s).replace(/"/g, '""')}"`;
};

export async function monitoringRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;
  app.addHook('preHandler', app.authenticate);

  const scoped = <T>(req: FastifyRequest, orgId: string, fn: (client: Queryable, userId: string) => Promise<T>) => {
    const { userId } = requireAuth(req);
    return withOrgTx(db, { orgId, userId }, async (client) => {
      await requireAdmin(client, orgId, userId);
      return fn(client, userId);
    });
  };

  // ---- audit explorer ----------------------------------------------------------------

  app.get('/orgs/:orgId/events', async (req): Promise<OrgEvent[]> => {
    const { orgId } = parse(orgParam, req.params);
    const q = parse(auditQuery, req.query);
    return scoped(req, orgId, async (client) => {
      const { text, values } = eventQuery(orgId, q, q.limit);
      return (await client.query<EventRow>(text, values)).rows.map(toEvent);
    });
  });

  app.get('/orgs/:orgId/audit/export', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { orgId } = parse(orgParam, req.params);
    const q = parse(exportQuery, req.query);
    const rows = await scoped(req, orgId, async (client, userId) => {
      const { text, values } = eventQuery(orgId, q, 100_000);
      const result = (await client.query<EventRow>(text, values)).rows;
      // Exporting the trail is itself an auditable action.
      await recordAudit(client, req, { userId, orgId, action: 'org.audit_exported', targetType: 'org', targetId: orgId, metadata: { format: q.format, count: result.length } });
      return result;
    });
    const stamp = new Date().toISOString().slice(0, 10);
    reply.header('content-disposition', `attachment; filename="enclavier-audit-${stamp}.${q.format === 'csv' ? 'csv' : 'ndjson'}"`);
    if (q.format === 'ndjson') {
      reply.type('application/x-ndjson');
      return rows.map((r) => JSON.stringify({ ...toEvent(r), orgHash: r.org_hash?.toString('hex') ?? null })).join('\n') + '\n';
    }
    reply.type('text/csv; charset=utf-8');
    const header = ['id', 'time', 'action', 'actor', 'target_type', 'target_id', 'ip', 'user_agent', 'metadata', 'org_seq', 'org_hash'];
    const lines = rows.map((r) =>
      [r.id, r.created_at.toISOString(), r.action, r.actor_email, r.target_type, r.target_id, r.ip, r.user_agent, r.metadata, r.org_seq, r.org_hash?.toString('hex')]
        .map(csvCell)
        .join(','),
    );
    return [header.join(','), ...lines].join('\r\n') + '\r\n';
  });

  app.get('/orgs/:orgId/audit/verify', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req): Promise<AuditVerifyResult> => {
    const { orgId } = parse(orgParam, req.params);
    return scoped(req, orgId, async (client) => ({ ...(await verifyOrgChain(client, orgId)), verifiedAt: new Date().toISOString() }));
  });

  // ---- log streaming destinations ----------------------------------------------------------

  async function toDestination(client: Queryable, r: {
    id: string; org_id: string; name: string; type: LogDestination['type']; enabled: boolean; config_enc: string;
    cursor_event_id: string; failures: number; last_success_at: Date | null; last_error: string | null;
  }): Promise<LogDestination> {
    const { rows } = await client.query<{ n: string }>('SELECT count(*) AS n FROM audit_events WHERE org_id = $1 AND id > $2', [r.org_id, r.cursor_event_id]);
    return {
      id: r.id,
      name: r.name,
      type: r.type,
      enabled: r.enabled,
      config: redact(JSON.parse(app.secrets.open(r.config_enc)) as DestinationConfig),
      lastSuccessAt: r.last_success_at?.toISOString() ?? null,
      lastError: r.last_error,
      failures: r.failures,
      backlog: Number(rows[0]!.n),
    };
  }

  function parseConfig(raw: unknown): DestinationConfig {
    const res = destinationConfig.safeParse(raw);
    if (!res.success) {
      const i = res.error.issues[0];
      throw badRequest(i ? `${i.path.join('.') || 'config'}: ${i.message}` : 'Invalid destination configuration');
    }
    return res.data;
  }

  app.get('/orgs/:orgId/log-destinations', async (req): Promise<LogDestination[]> => {
    const { orgId } = parse(orgParam, req.params);
    return scoped(req, orgId, async (client) => {
      const { rows } = await client.query('SELECT * FROM log_destinations WHERE org_id = $1 ORDER BY created_at', [orgId]);
      return Promise.all(rows.map((r) => toDestination(client, r)));
    });
  });

  app.post('/orgs/:orgId/log-destinations', async (req, reply) => {
    const { orgId } = parse(orgParam, req.params);
    const body = parse(destinationCreate, req.body);
    const cfg = parseConfig(body.config);
    const id = randomUUID();
    await scoped(req, orgId, async (client, userId) => {
      // Start from "now" unless the admin asked to replay history.
      const { rows } = await client.query<{ max: string | null }>('SELECT max(id) AS max FROM audit_events WHERE org_id = $1', [orgId]);
      await client.query(
        `INSERT INTO log_destinations (id, org_id, name, type, config_enc, cursor_event_id) VALUES ($1, $2, $3, $4, $5, $6)`,
        [id, orgId, body.name, cfg.type, app.secrets.seal(JSON.stringify(cfg)), body.backfill ? 0 : Number(rows[0]!.max ?? 0)],
      );
      await recordAudit(client, req, { userId, orgId, action: 'org.log_destination_created', targetType: 'log_destination', targetId: id, metadata: { type: cfg.type, name: body.name } });
    });
    return reply.status(201).send({ id });
  });

  app.put('/orgs/:orgId/log-destinations/:destId', async (req, reply) => {
    const { orgId, destId } = parse(destParam, req.params);
    const body = parse(destinationUpdate, req.body);
    await scoped(req, orgId, async (client, userId) => {
      const { rows } = await client.query<{ config_enc: string }>('SELECT config_enc FROM log_destinations WHERE org_id = $1 AND id = $2', [orgId, destId]);
      if (!rows[0]) throw notFound('Destination not found');
      const current = JSON.parse(app.secrets.open(rows[0].config_enc)) as DestinationConfig;
      const merged: Record<string, unknown> = { ...body.config, type: current.type };
      // Masked or blank credential fields mean "keep the stored secret".
      for (const f of SECRET_FIELDS[current.type]) {
        const v = merged[f];
        if (v === undefined || v === '' || (typeof v === 'string' && v.startsWith('••••'))) merged[f] = (current as Record<string, unknown>)[f];
      }
      const cfg = parseConfig(merged);
      await client.query(
        `UPDATE log_destinations SET name = $3, enabled = $4, config_enc = $5, failures = 0, next_attempt_at = now() WHERE org_id = $1 AND id = $2`,
        [orgId, destId, body.name, body.enabled, app.secrets.seal(JSON.stringify(cfg))],
      );
      await recordAudit(client, req, { userId, orgId, action: 'org.log_destination_updated', targetType: 'log_destination', targetId: destId, metadata: { enabled: body.enabled } });
    });
    return reply.status(204).send();
  });

  app.delete('/orgs/:orgId/log-destinations/:destId', async (req, reply) => {
    const { orgId, destId } = parse(destParam, req.params);
    await scoped(req, orgId, async (client, userId) => {
      const res = await client.query('DELETE FROM log_destinations WHERE org_id = $1 AND id = $2', [orgId, destId]);
      if (!res.rowCount) throw notFound('Destination not found');
      await recordAudit(client, req, { userId, orgId, action: 'org.log_destination_deleted', targetType: 'log_destination', targetId: destId });
    });
    return reply.status(204).send();
  });

  /** Sends one synthetic event so admins can check credentials and parsing on the SIEM side. */
  app.post('/orgs/:orgId/log-destinations/:destId/test', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req) => {
    const { orgId, destId } = parse(destParam, req.params);
    const { cfg, orgName, email } = await scoped(req, orgId, async (client, userId) => {
      const { rows } = await client.query<{ config_enc: string; org_name: string }>(
        'SELECT d.config_enc, o.name AS org_name FROM log_destinations d JOIN organizations o ON o.id = d.org_id WHERE d.org_id = $1 AND d.id = $2',
        [orgId, destId],
      );
      if (!rows[0]) throw notFound('Destination not found');
      const user = (await client.query<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId])).rows[0]!;
      return { cfg: JSON.parse(app.secrets.open(rows[0].config_enc)) as DestinationConfig, orgName: rows[0].org_name, email: user.email };
    });
    const event: StreamEvent = {
      id: 0,
      timestamp: new Date().toISOString(),
      action: 'enclavier.test_event',
      outcome: 'success',
      organization: { id: orgId, name: orgName },
      actor: { id: requireAuth(req).userId, email },
      target: { type: 'log_destination', id: destId },
      source: { ip: req.ip, userAgent: req.headers['user-agent'] ?? null },
      metadata: { note: 'Test event sent from the Enclavier admin console' },
      integrity: { orgSeq: null, orgHash: null, chainHash: '' },
    };
    try {
      await deliver(cfg, [event], config.ALLOW_PRIVATE_LOG_DESTINATIONS);
      return { ok: true, message: 'Test event delivered' };
    } catch (err) {
      return { ok: false, message: err instanceof DestinationError ? err.message : `Delivery failed: ${(err as Error).message}` };
    }
  });

  // ---- compliance posture ----------------------------------------------------------------

  app.get('/orgs/:orgId/compliance', async (req): Promise<ComplianceReport> => {
    const { orgId } = parse(orgParam, req.params);
    return scoped(req, orgId, async (client, userId) => {
      const policies = policiesToDto(await loadPolicies(client, orgId));
      const report = await buildComplianceReport(client, { orgId, userId, policies, publicUrl: config.PUBLIC_URL });
      await recordAudit(client, req, { userId, orgId, action: 'org.compliance_report_generated', targetType: 'org', targetId: orgId, metadata: report.summary });
      return report;
    });
  });
}
