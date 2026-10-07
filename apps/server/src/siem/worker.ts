import type { FastifyInstance } from 'fastify';
import { withTx, type Queryable } from '../db';
import { deliver, destinationConfig, outcomeOf, type DestinationConfig, type StreamEvent } from './destinations';

const BATCH = 500;
const MAX_BACKOFF_SECONDS = 3600;

interface EventRow {
  id: string;
  org_id: string;
  org_name: string;
  user_id: string | null;
  actor_email: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  user_agent: string | null;
  metadata: Record<string, unknown>;
  created_at: Date;
  org_seq: string | null;
  org_hash: Buffer | null;
  hash: Buffer;
}

export function toStreamEvent(r: EventRow): StreamEvent {
  return {
    id: Number(r.id),
    timestamp: r.created_at.toISOString(),
    action: r.action,
    outcome: outcomeOf(r.action),
    organization: { id: r.org_id, name: r.org_name },
    actor: r.user_id ? { id: r.user_id, email: r.actor_email } : null,
    target: { type: r.target_type, id: r.target_id },
    source: { ip: r.ip, userAgent: r.user_agent },
    metadata: r.metadata,
    integrity: { orgSeq: r.org_seq ? Number(r.org_seq) : null, orgHash: r.org_hash?.toString('hex') ?? null, chainHash: r.hash.toString('hex') },
  };
}

export async function loadStreamEvents(client: Queryable, orgId: string, afterId: number, limit = BATCH): Promise<StreamEvent[]> {
  const { rows } = await client.query<EventRow>(
    `SELECT e.id, e.org_id, o.name AS org_name, e.user_id, u.email AS actor_email, e.action, e.target_type, e.target_id,
            e.ip, e.user_agent, e.metadata, e.created_at, e.org_seq, e.org_hash, e.hash
       FROM audit_events e
       JOIN organizations o ON o.id = e.org_id
       LEFT JOIN users u ON u.id = e.user_id
      WHERE e.org_id = $1 AND e.id > $2
      ORDER BY e.id LIMIT $3`,
    [orgId, afterId, limit],
  );
  return rows.map(toStreamEvent);
}

/**
 * One delivery pass: picks due destinations one at a time (SKIP LOCKED, so
 * several server replicas can run the worker safely) and ships the next batch.
 * Delivery is at-least-once; receivers can de-duplicate on event id.
 */
export async function deliverDue(app: FastifyInstance, maxDestinations = 20): Promise<number> {
  let delivered = 0;
  for (let i = 0; i < maxDestinations; i++) {
    const handled = await withTx(app.db, async (client) => {
      const { rows } = await client.query<{ id: string; org_id: string; config_enc: string; cursor_event_id: string; failures: number }>(
        `SELECT id, org_id, config_enc, cursor_event_id, failures FROM log_destinations
          WHERE enabled AND next_attempt_at <= now()
          ORDER BY next_attempt_at LIMIT 1 FOR UPDATE SKIP LOCKED`,
      );
      const d = rows[0];
      if (!d) return false;
      const events = await loadStreamEvents(client, d.org_id, Number(d.cursor_event_id));
      if (events.length === 0) {
        await client.query(`UPDATE log_destinations SET next_attempt_at = now() + interval '5 seconds' WHERE id = $1`, [d.id]);
        return true;
      }
      try {
        const config = destinationConfig.parse(JSON.parse(app.secrets.open(d.config_enc))) as DestinationConfig;
        await deliver(config, events, app.config.ALLOW_PRIVATE_LOG_DESTINATIONS);
        await client.query(
          `UPDATE log_destinations SET cursor_event_id = $2, failures = 0, last_error = NULL, last_success_at = now(), next_attempt_at = now()
            WHERE id = $1`,
          [d.id, events.at(-1)!.id],
        );
        delivered += events.length;
      } catch (err) {
        const backoff = Math.min(MAX_BACKOFF_SECONDS, 10 * 2 ** Math.min(d.failures, 12));
        await client.query(
          `UPDATE log_destinations SET failures = failures + 1, last_error = $2, next_attempt_at = now() + make_interval(secs => $3) WHERE id = $1`,
          [d.id, (err as Error).message.slice(0, 500), backoff],
        );
        app.log.warn({ destination: d.id, err: (err as Error).message }, 'Log stream delivery failed');
      }
      return true;
    });
    if (!handled) break;
  }
  return delivered;
}

/** Starts the background streaming loop. Returns a stop function. */
export function startLogStreaming(app: FastifyInstance): () => Promise<void> {
  let stopped = false;
  let running: Promise<unknown> = Promise.resolve();
  const tick = () => {
    if (stopped) return;
    running = deliverDue(app)
      .catch((err) => app.log.error({ err }, 'Log streaming pass failed'))
      .finally(() => {
        if (!stopped) timer = setTimeout(tick, app.config.LOG_STREAM_INTERVAL_MS);
      });
  };
  let timer = setTimeout(tick, app.config.LOG_STREAM_INTERVAL_MS);
  return async () => {
    stopped = true;
    clearTimeout(timer);
    await running;
  };
}
