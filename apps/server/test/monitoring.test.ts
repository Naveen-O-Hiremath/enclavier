import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHmac } from 'node:crypto';
import { createServer as createHttpServer, type IncomingMessage, type Server } from 'node:http';
import { createServer as createTcpServer, type Server as TcpServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import type { FastifyInstance } from 'fastify';
import { encryptCollectionName, generateOrgKey, parseTotp, sealOrgKey, toB64, totpCode, uuid } from '@enclavier/crypto';
import type { AuditVerifyResult, ComplianceReport, LogDestination, OrgEvent, SyncResponse } from '@enclavier/shared';
import type { Db } from '../src/db';
import { deliverDue } from '../src/siem/worker';
import { DATABASE_URL, registerUser, resetDb, setupApp, type TestUser } from './helpers';

interface Captured {
  headers: IncomingMessage['headers'];
  body: string;
  url: string;
}

/** Tiny HTTP receiver standing in for a SIEM / HIBP endpoint. */
async function receiver(respond: (req: Captured) => { status: number; body?: string } = () => ({ status: 200 })) {
  const calls: Captured[] = [];
  const server: Server = createHttpServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const call = { headers: req.headers, body, url: req.url ?? '' };
      calls.push(call);
      const out = respond(call);
      res.writeHead(out.status, { 'content-type': 'text/plain' }).end(out.body ?? 'ok');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { calls, url, close: () => new Promise<void>((r) => server.close(() => r())) };
}

describe.skipIf(!DATABASE_URL)('Phase 4: audit, streaming, breach checks, policies, compliance (integration)', () => {
  let db: Db;
  let app: FastifyInstance; // private destinations allowed (self-hosted mode)
  let saas: FastifyInstance; // default: SSRF guard on
  let hibp: Awaited<ReturnType<typeof receiver>>;
  let owner: TestUser;
  const orgId = uuid();
  const collectionId = uuid();
  const orgKey = generateOrgKey();

  const sync = async (u: TestUser) => (await app.inject({ method: 'GET', url: '/api/sync', headers: u.auth })).json() as SyncResponse;

  beforeAll(async () => {
    db = await resetDb();
    hibp = await receiver((c) => ({ status: 200, body: c.url.endsWith('/ABCDE') ? '0018A45C4D1DEF81644B54AB7F969B88D65:3\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0' : '' }));
    ({ app } = await setupApp(db, { ALLOW_PRIVATE_LOG_DESTINATIONS: 'true', HIBP_API_URL: hibp.url }));
    ({ app: saas } = await setupApp(db, { HIBP_API_URL: '' }));
    owner = await registerUser(app, 'owner@audit.test');
    await app.inject({
      method: 'POST',
      url: '/api/orgs',
      headers: owner.auth,
      payload: {
        id: orgId,
        name: 'Audited Inc',
        protectedOrgKey: sealOrgKey(toB64(owner.keys.publicKey), orgKey, orgId),
        defaultCollection: { id: collectionId, name: encryptCollectionName(orgKey, collectionId, 'Default') },
      },
    });
    await app.inject({ method: 'POST', url: `/api/orgs/${orgId}/members/invite`, headers: owner.auth, payload: { emails: ['a@audit.test', 'b@audit.test'], role: 'member' } });
  });

  afterAll(async () => {
    await app?.close();
    await saas?.close();
    await hibp?.close();
    await db?.end();
  });

  describe('audit explorer', () => {
    it('keeps a per-organization hash chain and verifies it', async () => {
      const res = (await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/audit/verify`, headers: owner.auth })).json() as AuditVerifyResult;
      expect(res).toMatchObject({ ok: true, legacy: 0 });
      expect(res.checked).toBeGreaterThanOrEqual(3); // org.created + 2 invites
      expect(res.head?.seq).toBe(res.checked);
    });

    it('filters events by action prefix, actor and time', async () => {
      const get = (qs: string) => app.inject({ method: 'GET', url: `/api/orgs/${orgId}/events?${qs}`, headers: owner.auth }).then((r) => r.json() as OrgEvent[]);
      const invites = await get('action=member.');
      expect(invites.map((e) => e.action)).toEqual(['member.invited', 'member.invited']);
      expect(invites[0]!.orgSeq).toBeGreaterThan(0);
      expect(await get('actor=nobody@')).toHaveLength(0);
      expect(await get(`from=${encodeURIComponent(new Date(Date.now() + 60_000).toISOString())}`)).toHaveLength(0);
    });

    it('exports CSV and NDJSON, and audits the export itself', async () => {
      const csv = await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/audit/export?format=csv`, headers: owner.auth });
      expect(csv.statusCode).toBe(200);
      expect(csv.headers['content-type']).toContain('text/csv');
      const lines = csv.body.trim().split('\r\n');
      expect(lines[0]).toBe('id,time,action,actor,target_type,target_id,ip,user_agent,metadata,org_seq,org_hash');
      expect(lines.length).toBeGreaterThanOrEqual(4);
      const nd = await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/audit/export?format=ndjson`, headers: owner.auth });
      expect(nd.body.trim().split('\n').map((l) => JSON.parse(l).action)).toContain('org.audit_exported');
    });
  });

  describe('log streaming', () => {
    it('blocks destinations on private networks by default (SSRF)', async () => {
      const sink = await receiver();
      try {
        // The SaaS-mode app shares the DB; the destination itself is created by either app.
        const created = await saas.inject({
          method: 'POST',
          url: `/api/orgs/${orgId}/log-destinations`,
          headers: owner.auth,
          payload: { name: 'internal', config: { type: 'webhook', url: `${sink.url.replace('http:', 'https:')}/hook`, secret: 'x'.repeat(32) } },
        });
        const test = await saas.inject({ method: 'POST', url: `/api/orgs/${orgId}/log-destinations/${created.json().id}/test`, headers: owner.auth });
        expect(test.json()).toMatchObject({ ok: false });
        expect(test.json().message).toMatch(/private or internal/);
        expect(sink.calls).toHaveLength(0);
        await saas.inject({ method: 'DELETE', url: `/api/orgs/${orgId}/log-destinations/${created.json().id}`, headers: owner.auth });
      } finally {
        await sink.close();
      }
    });

    it('delivers signed webhook batches exactly from the cursor, and redacts secrets', async () => {
      const sink = await receiver();
      const secret = 'webhook-signing-secret-0123456789';
      try {
        const created = await app.inject({
          method: 'POST',
          url: `/api/orgs/${orgId}/log-destinations`,
          headers: owner.auth,
          payload: { name: 'SOC webhook', backfill: true, config: { type: 'webhook', url: `${sink.url}/hook`, secret } },
        });
        expect(created.statusCode).toBe(201);
        const id = created.json().id;

        const list = (await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/log-destinations`, headers: owner.auth })).json() as LogDestination[];
        const dest = list.find((d) => d.id === id)!;
        expect(dest.config.secret).toBe(`••••${secret.slice(-4)}`);
        expect(JSON.stringify(list)).not.toContain(secret);
        expect(dest.backlog).toBeGreaterThan(0);

        await deliverDue(app);
        expect(sink.calls).toHaveLength(1);
        const call = sink.calls[0]!;
        const [t, v1] = String(call.headers['x-enclavier-signature']).split(',').map((p) => p.split('=')[1]);
        expect(v1).toBe(createHmac('sha256', secret).update(`${t}.${call.body}`).digest('hex'));
        const batch = JSON.parse(call.body).events;
        expect(batch[0]).toMatchObject({ action: 'org.created', organization: { id: orgId, name: 'Audited Inc' } });
        expect(batch[0].integrity.orgHash).toMatch(/^[0-9a-f]{64}$/);

        // Nothing new → nothing sent. Then a new event is delivered alone.
        await db.query(`UPDATE log_destinations SET next_attempt_at = now()`);
        await deliverDue(app);
        expect(sink.calls).toHaveLength(1);
        await app.inject({ method: 'POST', url: `/api/orgs/${orgId}/members/invite`, headers: owner.auth, payload: { emails: ['c@audit.test'], role: 'member' } });
        await db.query(`UPDATE log_destinations SET next_attempt_at = now()`);
        await deliverDue(app);
        expect(sink.calls).toHaveLength(2);
        expect(JSON.parse(sink.calls[1]!.body).events.map((e: { action: string }) => e.action)).toEqual(['member.invited']);

        // Saving with the masked secret keeps the original one.
        await app.inject({
          method: 'PUT',
          url: `/api/orgs/${orgId}/log-destinations/${id}`,
          headers: owner.auth,
          payload: { name: 'SOC webhook', enabled: true, config: { ...dest.config } },
        });
        const test = await app.inject({ method: 'POST', url: `/api/orgs/${orgId}/log-destinations/${id}/test`, headers: owner.auth });
        expect(test.json().ok).toBe(true);
        const last = sink.calls.at(-1)!;
        const [t2, sig2] = String(last.headers['x-enclavier-signature']).split(',').map((p) => p.split('=')[1]);
        expect(sig2).toBe(createHmac('sha256', secret).update(`${t2}.${last.body}`).digest('hex'));
        await app.inject({ method: 'DELETE', url: `/api/orgs/${orgId}/log-destinations/${id}`, headers: owner.auth });
      } finally {
        await sink.close();
      }
    });

    it('backs off and records the error when the SIEM rejects a batch', async () => {
      const sink = await receiver(() => ({ status: 503, body: 'indexer busy' }));
      try {
        const id = (
          await app.inject({
            method: 'POST',
            url: `/api/orgs/${orgId}/log-destinations`,
            headers: owner.auth,
            payload: { name: 'Splunk', backfill: true, config: { type: 'splunk', url: `${sink.url}/services/collector/event`, token: 'splunk-hec-token-1' } },
          })
        ).json().id;
        await deliverDue(app);
        expect(sink.calls[0]!.headers.authorization).toBe('Splunk splunk-hec-token-1');
        const firstLine = JSON.parse(sink.calls[0]!.body.split('\n')[0]!);
        expect(firstLine).toMatchObject({ sourcetype: 'enclavier:audit', event: { organization: { id: orgId } } });

        const { rows } = await db.query('SELECT failures, last_error, cursor_event_id, next_attempt_at > now() AS delayed FROM log_destinations WHERE id = $1', [id]);
        expect(rows[0]).toMatchObject({ failures: 1, cursor_event_id: '0', delayed: true });
        expect(rows[0].last_error).toContain('503');
        await deliverDue(app); // not due yet: no retry storm
        expect(sink.calls).toHaveLength(1);
        await app.inject({ method: 'DELETE', url: `/api/orgs/${orgId}/log-destinations/${id}`, headers: owner.auth });
      } finally {
        await sink.close();
      }
    });

    it('streams RFC 5424 syslog over TCP with octet framing', async () => {
      let received = '';
      const tcp: TcpServer = createTcpServer((s) => s.on('data', (d) => (received += d.toString())));
      await new Promise<void>((r) => tcp.listen(0, '127.0.0.1', r));
      try {
        const port = (tcp.address() as AddressInfo).port;
        const id = (
          await app.inject({
            method: 'POST',
            url: `/api/orgs/${orgId}/log-destinations`,
            headers: owner.auth,
            payload: { name: 'syslog', config: { type: 'syslog', host: '127.0.0.1', port, protocol: 'tcp' } },
          })
        ).json().id;
        const test = await app.inject({ method: 'POST', url: `/api/orgs/${orgId}/log-destinations/${id}/test`, headers: owner.auth });
        expect(test.json().ok).toBe(true);
        await new Promise((r) => setTimeout(r, 100));
        const m = received.match(/^(\d+) (<134>1 \S+ \S+ enclavier - enclavier.test_event \[enclavier@32473 [^\]]+\] \{.*\})$/s);
        expect(m).not.toBeNull();
        expect(Number(m![1])).toBe(Buffer.byteLength(m![2]!));
        await app.inject({ method: 'DELETE', url: `/api/orgs/${orgId}/log-destinations/${id}`, headers: owner.auth });
      } finally {
        await new Promise<void>((r) => tcp.close(() => r()));
      }
    });

    it('validates destination configuration', async () => {
      const bad = await app.inject({
        method: 'POST',
        url: `/api/orgs/${orgId}/log-destinations`,
        headers: owner.auth,
        payload: { name: 'x', config: { type: 'datadog', site: 'evil.example', apiKey: 'k'.repeat(32) } },
      });
      expect(bad.statusCode).toBe(400);
    });
  });

  describe('breach checks (k-anonymity)', () => {
    it('proxies only the 5-character prefix, with padding, and caches', async () => {
      const r1 = await app.inject({ method: 'GET', url: '/api/breach/range/abcde', headers: owner.auth });
      expect(r1.statusCode).toBe(200);
      expect(r1.body).toContain('0018A45C4D1DEF81644B54AB7F969B88D65:3');
      expect(hibp.calls[0]!.url).toBe('/range/ABCDE');
      expect(hibp.calls[0]!.headers['add-padding']).toBe('true');
      await app.inject({ method: 'GET', url: '/api/breach/range/ABCDE', headers: owner.auth });
      expect(hibp.calls).toHaveLength(1);
      expect((await app.inject({ method: 'GET', url: '/api/breach/range/ABCDEF', headers: owner.auth })).statusCode).toBe(400);
      expect((await app.inject({ method: 'GET', url: '/api/breach/range/ABCDE' })).statusCode).toBe(401);
    });

    it('can be disabled for air-gapped installs', async () => {
      expect((await saas.inject({ method: 'GET', url: '/api/breach/status', headers: owner.auth })).json()).toEqual({ passwords: false, accounts: false });
      expect((await saas.inject({ method: 'GET', url: '/api/breach/range/ABCDE', headers: owner.auth })).statusCode).toBe(503);
    });
  });

  describe('policy engine & compliance report', () => {
    const put = (payload: object) => app.inject({ method: 'PUT', url: `/api/orgs/${orgId}/policies`, headers: owner.auth, payload });
    const report = async () => (await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/compliance`, headers: owner.auth })).json() as ComplianceReport;

    it('stores and distributes policies', async () => {
      expect((await put({ type: 'master_password', enabled: true, minLength: 4, minScore: 3 })).statusCode).toBe(400);
      expect((await put({ type: 'master_password', enabled: true, minLength: 14, minScore: 3 })).statusCode).toBe(200);
      await put({ type: 'vault_timeout', enabled: true, maxMinutes: 10 });
      await put({ type: 'clipboard', enabled: true, maxSeconds: 20 });
      await put({ type: 'password_generator', enabled: true, minLength: 20, requireSymbols: true });
      const res = await put({ type: 'disable_export', enabled: true });
      expect(res.json()).toMatchObject({
        masterPassword: { minLength: 14, minScore: 3 },
        vaultTimeout: { maxMinutes: 10 },
        clipboard: { maxSeconds: 20 },
        passwordGenerator: { minLength: 20, requireSymbols: true, requireUppercase: true },
        disableExport: true,
      });
      expect((await sync(owner)).organizations[0]!.policies.vaultTimeout).toEqual({ maxMinutes: 10 });
    });

    it('reports posture that improves as controls are configured', async () => {
      const before = await report();
      const byId = (r: ComplianceReport, id: string) => r.controls.find((c) => c.id === id)!;
      expect(byId(before, 'mfa-enforced').status).toBe('fail');
      expect(byId(before, 'password-policy').status).toBe('pass');
      expect(byId(before, 'session-timeout').status).toBe('pass');
      expect(byId(before, 'audit-integrity').status).toBe('pass');
      expect(byId(before, 'encryption').status).toBe('pass'); // PUBLIC_URL is https in tests
      expect(Object.values(before.summary).reduce((a, b) => a + b, 0)).toBe(before.controls.length);
      expect(before.auditChainHead?.hash).toMatch(/^[0-9a-f]{64}$/);
      for (const c of before.controls) expect(c.references.length).toBeGreaterThan(0);

      const setup = (await app.inject({ method: 'POST', url: '/api/account/2fa/totp/setup', headers: owner.auth })).json();
      await app.inject({ method: 'POST', url: '/api/account/2fa/totp/enable', headers: owner.auth, payload: { setupToken: setup.setupToken, code: totpCode(parseTotp(setup.secret)).code } });
      await put({ type: 'require_2fa', enabled: true });

      const after = await report();
      expect(byId(after, 'mfa-enforced').status).toBe('pass');
      expect(byId(after, 'mfa-coverage').status).toBe('pass');
      expect(after.summary.pass).toBeGreaterThan(before.summary.pass);
      const soc2 = after.frameworks.find((f) => f.framework === 'SOC 2')!;
      expect(soc2.total).toBeGreaterThan(0);
    });
  });

  describe('tamper detection (runs last: it corrupts the log on purpose)', () => {
    it('detects modified and deleted events in the org chain', async () => {
      const verify = async () => (await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/audit/verify`, headers: owner.auth })).json() as AuditVerifyResult;
      // Simulate a DBA bypassing the append-only trigger.
      await db.query('ALTER TABLE audit_events DISABLE TRIGGER USER');
      try {
        await db.query(`UPDATE audit_events SET metadata = '{"email":"forged@evil.test"}' WHERE org_id = $1 AND org_seq = 2`, [orgId]);
        expect(await verify()).toMatchObject({ ok: false, brokenAtSeq: 2, reason: 'event contents were modified' });
        await db.query('DELETE FROM audit_events WHERE org_id = $1 AND org_seq = 2', [orgId]);
        expect(await verify()).toMatchObject({ ok: false, reason: 'event #2 is missing (deleted)' });
      } finally {
        await db.query('ALTER TABLE audit_events ENABLE TRIGGER USER');
      }
      const r = (await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/compliance`, headers: owner.auth })).json() as ComplianceReport;
      expect(r.controls.find((c) => c.id === 'audit-integrity')!.status).toBe('fail');
    });
  });
});
