import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';
import { createSocket } from 'node:dgram';
import { connect as netConnect } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { hostname as osHostname } from 'node:os';
import { z } from 'zod';
import { privateHostProblem } from '../net';

// ---- destination configuration ------------------------------------------------------

const httpsUrl = z.string().url().max(2000);

export const destinationConfig = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('webhook'),
    url: httpsUrl,
    /** HMAC-SHA256 signing secret; receivers verify X-Enclavier-Signature. */
    secret: z.string().min(16).max(200),
  }),
  z.object({
    type: z.literal('splunk'),
    /** e.g. https://splunk.example.com:8088/services/collector/event */
    url: httpsUrl,
    token: z.string().min(8).max(200),
    index: z.string().max(100).optional(),
    sourcetype: z.string().max(100).default('enclavier:audit'),
  }),
  z.object({
    type: z.literal('datadog'),
    site: z.enum(['datadoghq.com', 'datadoghq.eu', 'us3.datadoghq.com', 'us5.datadoghq.com', 'ap1.datadoghq.com', 'ddog-gov.com']),
    apiKey: z.string().min(16).max(200),
    service: z.string().max(100).default('enclavier'),
  }),
  z.object({
    type: z.literal('sentinel'),
    /** Microsoft Sentinel via the Azure Monitor Logs Ingestion API (DCE + DCR). */
    tenantId: z.string().uuid(),
    clientId: z.string().uuid(),
    clientSecret: z.string().min(8).max(500),
    endpoint: httpsUrl,
    dcrId: z.string().min(5).max(200),
    stream: z.string().min(3).max(200).default('Custom-EnclavierAudit_CL'),
  }),
  z.object({
    type: z.literal('sumologic'),
    /** Hosted HTTP source URL (contains its own token). */
    url: httpsUrl,
  }),
  z.object({
    type: z.literal('syslog'),
    host: z.string().min(1).max(255),
    port: z.number().int().min(1).max(65535).default(6514),
    protocol: z.enum(['tls', 'tcp', 'udp']).default('tls'),
    facility: z.number().int().min(0).max(23).default(16), // local0
    /** Optional PEM CA bundle for a private syslog CA. */
    caCert: z.string().max(20000).optional(),
  }),
]);
export type DestinationConfig = z.infer<typeof destinationConfig>;
export type DestinationType = DestinationConfig['type'];

/** Fields that are credentials: never returned to clients after saving. */
export const SECRET_FIELDS: Record<DestinationType, string[]> = {
  webhook: ['secret'],
  splunk: ['token'],
  datadog: ['apiKey'],
  sentinel: ['clientSecret'],
  sumologic: ['url'],
  syslog: [],
};

export function redact(config: DestinationConfig): Record<string, unknown> {
  const out: Record<string, unknown> = { ...config };
  for (const f of SECRET_FIELDS[config.type]) {
    const v = String(out[f] ?? '');
    out[f] = v ? `••••${v.slice(-4)}` : '';
  }
  return out;
}

// ---- normalized event ------------------------------------------------------------------

export interface StreamEvent {
  id: number;
  timestamp: string;
  action: string;
  outcome: 'success' | 'failure';
  organization: { id: string; name: string };
  actor: { id: string; email: string | null } | null;
  target: { type: string | null; id: string | null };
  source: { ip: string | null; userAgent: string | null };
  metadata: Record<string, unknown>;
  integrity: { orgSeq: number | null; orgHash: string | null; chainHash: string };
}

const FAILURE = /failed|reuse_detected|revoked|removed|deleted|break_glass/;
export const outcomeOf = (action: string): 'success' | 'failure' =>
  /failed|reuse_detected/.test(action) ? 'failure' : 'success';
const severityOf = (action: string) => (FAILURE.test(action) ? 4 /* warning */ : 6 /* informational */);

// ---- SSRF protection ---------------------------------------------------------------------

export class DestinationError extends Error {}

/**
 * Refuses destinations on private, loopback and link-local networks (SSRF),
 * unless the operator explicitly allows it for self-hosted internal SIEMs.
 */
export async function assertPublicHost(host: string, allowPrivate: boolean): Promise<void> {
  if (allowPrivate) return;
  const problem = await privateHostProblem(host);
  if (problem?.startsWith('Cannot resolve')) throw new DestinationError(problem);
  if (problem) {
    throw new DestinationError(`${problem}. Set ALLOW_PRIVATE_LOG_DESTINATIONS=true on self-hosted servers to allow internal SIEMs.`);
  }
}

async function post(url: string, init: { headers: Record<string, string>; body: string }, allowPrivate: boolean): Promise<void> {
  const u = new URL(url);
  if (u.protocol !== 'https:' && !(allowPrivate && u.protocol === 'http:')) throw new DestinationError('Destination URL must use https');
  await assertPublicHost(u.hostname.replace(/^\[|\]$/g, ''), allowPrivate);
  let res: Response;
  try {
    res = await fetch(u, {
      method: 'POST',
      headers: init.headers,
      body: init.body,
      redirect: 'manual', // a redirect could point at an internal address
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    throw new DestinationError(`Could not reach ${u.host}: ${(err as Error).message}`);
  }
  if (res.status >= 300) {
    const text = (await res.text().catch(() => '')).slice(0, 300);
    throw new DestinationError(`${u.host} responded ${res.status}${text ? `: ${text}` : ''}`);
  }
}

// ---- senders -------------------------------------------------------------------------------

const sentinelTokens = new Map<string, { token: string; expires: number }>();

async function sentinelToken(c: Extract<DestinationConfig, { type: 'sentinel' }>): Promise<string> {
  const key = `${c.tenantId}:${c.clientId}`;
  const cached = sentinelTokens.get(key);
  if (cached && cached.expires > Date.now() + 60_000) return cached.token;
  const res = await fetch(`https://login.microsoftonline.com/${c.tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: c.clientId,
      client_secret: c.clientSecret,
      grant_type: 'client_credentials',
      scope: 'https://monitor.azure.com//.default',
    }),
    signal: AbortSignal.timeout(10_000),
  }).catch((err: Error) => {
    throw new DestinationError(`Microsoft Entra token request failed: ${err.message}`);
  });
  if (!res.ok) throw new DestinationError(`Microsoft Entra rejected the app credentials (${res.status})`);
  const body = (await res.json()) as { access_token: string; expires_in: number };
  sentinelTokens.set(key, { token: body.access_token, expires: Date.now() + body.expires_in * 1000 });
  return body.access_token;
}

function syslogLine(e: StreamEvent, facility: number): string {
  const pri = facility * 8 + severityOf(e.action);
  const host = osHostname().replace(/\s/g, '') || '-';
  const msgId = e.action.replace(/[^A-Za-z0-9._-]/g, '').slice(0, 32) || '-';
  const sd = `[enclavier@32473 org="${e.organization.id}" event="${e.id}" outcome="${e.outcome}"]`;
  return `<${pri}>1 ${e.timestamp} ${host} enclavier - ${msgId} ${sd} ${JSON.stringify(e)}`;
}

async function sendSyslog(c: Extract<DestinationConfig, { type: 'syslog' }>, events: StreamEvent[], allowPrivate: boolean): Promise<void> {
  await assertPublicHost(c.host, allowPrivate);
  const lines = events.map((e) => syslogLine(e, c.facility));
  if (c.protocol === 'udp') {
    const socket = createSocket(isIP(c.host) === 6 ? 'udp6' : 'udp4');
    try {
      for (const line of lines) {
        await new Promise<void>((resolve, reject) => socket.send(Buffer.from(line), c.port, c.host, (err) => (err ? reject(err) : resolve())));
      }
    } finally {
      socket.close();
    }
    return;
  }
  // TCP / TLS with octet-counting framing (RFC 6587 / RFC 5425).
  const payload = lines.map((l) => `${Buffer.byteLength(l)} ${l}`).join('');
  await new Promise<void>((resolve, reject) => {
    const socket =
      c.protocol === 'tls'
        ? tlsConnect({ host: c.host, port: c.port, servername: isIP(c.host) ? undefined : c.host, ca: c.caCert || undefined })
        : netConnect({ host: c.host, port: c.port });
    socket.setTimeout(10_000, () => socket.destroy(new Error('timed out')));
    socket.once('error', (err) => reject(new DestinationError(`syslog ${c.host}:${c.port}: ${err.message}`)));
    socket.once(c.protocol === 'tls' ? 'secureConnect' : 'connect', () => socket.end(payload, () => resolve()));
  });
}

/** Delivers a batch. Throws DestinationError on any failure so the worker can retry. */
export async function deliver(config: DestinationConfig, events: StreamEvent[], allowPrivate: boolean): Promise<void> {
  if (events.length === 0) return;
  switch (config.type) {
    case 'webhook': {
      const body = JSON.stringify({ source: 'enclavier', events });
      const ts = Math.floor(Date.now() / 1000);
      const sig = createHmac('sha256', config.secret).update(`${ts}.${body}`).digest('hex');
      return post(config.url, { headers: { 'content-type': 'application/json', 'x-enclavier-signature': `t=${ts},v1=${sig}` }, body }, allowPrivate);
    }
    case 'splunk': {
      const body = events
        .map((e) => JSON.stringify({ time: Date.parse(e.timestamp) / 1000, sourcetype: config.sourcetype, source: 'enclavier', ...(config.index ? { index: config.index } : {}), event: e }))
        .join('\n');
      return post(config.url, { headers: { authorization: `Splunk ${config.token}`, 'content-type': 'application/json' }, body }, allowPrivate);
    }
    case 'datadog': {
      const body = JSON.stringify(
        events.map((e) => ({
          ddsource: 'enclavier',
          service: config.service,
          status: e.outcome === 'failure' ? 'warn' : 'info',
          ddtags: `org:${e.organization.id},action:${e.action}`,
          message: `${e.actor?.email ?? 'system'} ${e.action}`,
          enclavier: e,
        })),
      );
      return post(`https://http-intake.logs.${config.site}/api/v2/logs`, { headers: { 'dd-api-key': config.apiKey, 'content-type': 'application/json' }, body }, allowPrivate);
    }
    case 'sentinel': {
      const token = await sentinelToken(config);
      const body = JSON.stringify(
        events.map((e) => ({
          TimeGenerated: e.timestamp,
          Action: e.action,
          Outcome: e.outcome,
          OrganizationId: e.organization.id,
          ActorEmail: e.actor?.email ?? null,
          TargetType: e.target.type,
          TargetId: e.target.id,
          SourceIp: e.source.ip,
          EventId: e.id,
          RawEvent: JSON.stringify(e),
        })),
      );
      const url = `${config.endpoint.replace(/\/$/, '')}/dataCollectionRules/${encodeURIComponent(config.dcrId)}/streams/${encodeURIComponent(config.stream)}?api-version=2023-01-01`;
      return post(url, { headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body }, allowPrivate);
    }
    case 'sumologic':
      return post(config.url, { headers: { 'content-type': 'application/json', 'x-sumo-category': 'enclavier/audit' }, body: events.map((e) => JSON.stringify(e)).join('\n') }, allowPrivate);
    case 'syslog':
      return sendSyslog(config, events, allowPrivate);
  }
}
