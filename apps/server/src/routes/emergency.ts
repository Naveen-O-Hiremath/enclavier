import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  emergencyAcceptRequest,
  emergencyConfirmRequest,
  emergencyInviteRequest,
  type EmergencyGrant,
  type EmergencyOverview,
  type EmergencyVault,
} from '@enclavier/shared';
import { requireAuth } from '../app';
import { recordAudit, type AuditAction } from '../audit';
import { withTx, type Queryable } from '../db';
import { badRequest, conflict, forbidden, notFound, parse } from '../errors';
import { newRefreshToken, sha256 } from '../security';
import { notify } from '../twofactor';
import { toItem, type ItemRow } from './vault';

const idParam = z.object({ id: z.string().uuid() });

interface GrantRow {
  id: string;
  grantor_id: string;
  grantee_id: string | null;
  grantee_email: string;
  status: EmergencyGrant['status'];
  wait_days: number;
  key_sealed: string | null;
  invite_token_hash: Buffer | null;
  recovery_initiated_at: Date | null;
}

const autoApproveAt = (g: GrantRow) =>
  g.status === 'recovery_initiated' && g.recovery_initiated_at ? new Date(g.recovery_initiated_at.getTime() + g.wait_days * 86_400_000) : null;

/**
 * Emergency access: a trusted contact can request read-only access to the
 * grantor's personal vault. It unlocks after the waiting period unless the
 * grantor rejects it first. The grantor's user key is sealed to the grantee's
 * public key when the grantor confirms; the server only enforces the timing.
 */
export async function emergencyRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;
  app.addHook('preHandler', app.authenticate);

  const audit = (client: Queryable, req: FastifyRequest, action: AuditAction, grantId: string, metadata?: Record<string, unknown>) =>
    recordAudit(client, req, { userId: req.auth!.userId, action, targetType: 'emergency_access', targetId: grantId, metadata });

  const userById = async (client: Queryable, id: string) =>
    (await client.query<{ email: string; name: string; public_key: string }>('SELECT email, name, public_key FROM users WHERE id = $1', [id])).rows[0]!;

  /** Promotes an initiated request whose waiting period has elapsed. */
  async function settle(client: Queryable, g: GrantRow): Promise<GrantRow> {
    const at = autoApproveAt(g);
    if (at && at <= new Date()) {
      await client.query(`UPDATE emergency_access SET status = 'recovery_approved', updated_at = now() WHERE id = $1`, [g.id]);
      return { ...g, status: 'recovery_approved' };
    }
    return g;
  }

  async function load(client: Queryable, id: string, lock = false): Promise<GrantRow> {
    const { rows } = await client.query<GrantRow>(`SELECT * FROM emergency_access WHERE id = $1 ${lock ? 'FOR UPDATE' : ''}`, [id]);
    if (!rows[0]) throw notFound('Emergency access not found');
    return settle(client, rows[0]);
  }

  app.get('/', async (req): Promise<EmergencyOverview> => {
    const { userId } = requireAuth(req);
    return withTx(db, async (client) => {
      const { rows } = await client.query<GrantRow & { grantor_email: string; grantor_name: string; grantee_name: string | null; grantee_public_key: string | null }>(
        `SELECT e.*, gr.email AS grantor_email, gr.name AS grantor_name, ge.name AS grantee_name, ge.public_key AS grantee_public_key
           FROM emergency_access e
           JOIN users gr ON gr.id = e.grantor_id
           LEFT JOIN users ge ON ge.id = e.grantee_id
          WHERE e.grantor_id = $1 OR e.grantee_id = $1
          ORDER BY e.created_at`,
        [userId],
      );
      const granted: EmergencyGrant[] = [];
      const trustedBy: EmergencyGrant[] = [];
      for (const raw of rows) {
        const g = { ...raw, ...(await settle(client, raw)) };
        const base = {
          id: g.id,
          status: g.status,
          waitDays: g.wait_days,
          recoveryInitiatedAt: g.recovery_initiated_at?.toISOString() ?? null,
          autoApproveAt: autoApproveAt(g)?.toISOString() ?? null,
        };
        if (g.grantor_id === userId) {
          granted.push({ ...base, email: g.grantee_email, name: g.grantee_name, publicKey: g.status === 'invited' ? null : g.grantee_public_key });
        } else {
          trustedBy.push({ ...base, email: g.grantor_email, name: g.grantor_name, publicKey: null });
        }
      }
      return { granted, trustedBy };
    });
  });

  app.post('/invite', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { userId } = requireAuth(req);
    const body = parse(emergencyInviteRequest, req.body);
    const id = randomUUID();
    const token = newRefreshToken();
    const me = await withTx(db, async (client) => {
      const me = await userById(client, userId);
      if (me.email === body.email) throw badRequest('You cannot be your own emergency contact');
      const res = await client.query(
        `INSERT INTO emergency_access (id, grantor_id, grantee_email, status, wait_days, invite_token_hash)
         VALUES ($1, $2, $3, 'invited', $4, $5) ON CONFLICT (grantor_id, grantee_email) DO NOTHING`,
        [id, userId, body.email, body.waitDays, sha256(token)],
      );
      if (!res.rowCount) throw conflict('This person is already an emergency contact');
      await audit(client, req, 'emergency.invited', id, { email: body.email, waitDays: body.waitDays });
      return me;
    });
    const link = `${config.PUBLIC_URL.replace(/\/$/, '')}/emergency/accept?id=${id}&token=${token}`;
    void notify(
      app,
      body.email,
      `${me.name} named you an emergency contact on Enclavier`,
      [
        `**${me.name}** (${me.email}) asked you to be their emergency contact on Enclavier.`,
        `If something happens to them, you can request read-only access to their vault. Access is granted after **${body.waitDays} day(s)** unless they reject the request.`,
        "You'll need an Enclavier account with this e-mail address to accept.",
      ],
      { label: 'Accept', url: link },
    );
    return reply.status(201).send({ id });
  });

  app.post('/accept', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { userId } = requireAuth(req);
    const body = parse(emergencyAcceptRequest, req.body);
    const grantor = await withTx(db, async (client) => {
      const g = await load(client, body.id, true);
      const me = await userById(client, userId);
      if (g.status !== 'invited' || !g.invite_token_hash || !sha256(body.token).equals(g.invite_token_hash)) {
        throw notFound('This invitation is invalid or was already used');
      }
      if (g.grantee_email !== me.email) throw forbidden(`This invitation was sent to ${g.grantee_email}`);
      await client.query(
        `UPDATE emergency_access SET grantee_id = $2, status = 'accepted', invite_token_hash = NULL, updated_at = now() WHERE id = $1`,
        [g.id, userId],
      );
      await audit(client, req, 'emergency.accepted', g.id);
      return userById(client, g.grantor_id);
    });
    void notify(app, grantor.email, 'Your emergency contact accepted', [
      'Your emergency contact accepted the invitation. Open **Settings → Emergency access** in Enclavier and confirm them to complete the setup.',
    ]);
    return reply.status(204).send();
  });

  /** The grantor's client seals their user key to the grantee's public key. */
  app.post('/:id/confirm', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    const { keySealed } = parse(emergencyConfirmRequest, req.body);
    await withTx(db, async (client) => {
      const g = await load(client, id, true);
      if (g.grantor_id !== userId) throw notFound('Emergency access not found');
      if (g.status !== 'accepted') throw badRequest('The contact has not accepted yet, or is already confirmed');
      await client.query(`UPDATE emergency_access SET status = 'confirmed', key_sealed = $2, updated_at = now() WHERE id = $1`, [id, keySealed]);
      await audit(client, req, 'emergency.confirmed', id);
    });
    return reply.status(204).send();
  });

  app.post('/:id/initiate', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    const info = await withTx(db, async (client) => {
      const g = await load(client, id, true);
      if (g.grantee_id !== userId) throw notFound('Emergency access not found');
      if (g.status !== 'confirmed') throw badRequest('Access can only be requested once the contact is confirmed');
      await client.query(`UPDATE emergency_access SET status = 'recovery_initiated', recovery_initiated_at = now(), updated_at = now() WHERE id = $1`, [id]);
      await audit(client, req, 'emergency.recovery_initiated', id);
      return { grantor: await userById(client, g.grantor_id), grantee: await userById(client, userId), waitDays: g.wait_days };
    });
    void notify(
      app,
      info.grantor.email,
      `${info.grantee.name} requested emergency access to your Enclavier vault`,
      [
        `**${info.grantee.name}** (${info.grantee.email}) requested emergency access to your vault.`,
        `They will get read-only access in **${info.waitDays} day(s)** unless you reject the request in **Settings → Emergency access**.`,
      ],
      { label: 'Review request', url: `${config.PUBLIC_URL.replace(/\/$/, '')}/settings` },
    );
    return reply.status(204).send();
  });

  for (const decision of ['approve', 'reject'] as const) {
    app.post(`/:id/${decision}`, async (req, reply) => {
      const { userId } = requireAuth(req);
      const { id } = parse(idParam, req.params);
      const grantee = await withTx(db, async (client) => {
        const g = await load(client, id, true);
        if (g.grantor_id !== userId) throw notFound('Emergency access not found');
        if (g.status !== 'recovery_initiated') throw badRequest('There is no pending request');
        await client.query(
          `UPDATE emergency_access SET status = $2, recovery_initiated_at = ${decision === 'reject' ? 'NULL' : 'recovery_initiated_at'}, updated_at = now() WHERE id = $1`,
          [id, decision === 'approve' ? 'recovery_approved' : 'confirmed'],
        );
        await audit(client, req, decision === 'approve' ? 'emergency.recovery_approved' : 'emergency.recovery_rejected', id);
        return userById(client, g.grantee_id!);
      });
      void notify(app, grantee.email, `Emergency access ${decision === 'approve' ? 'approved' : 'rejected'}`, [
        decision === 'approve'
          ? 'Your emergency access request was approved. You can now view the vault from **Settings → Emergency access**.'
          : 'Your emergency access request was rejected by the account owner.',
      ]);
      return reply.status(204).send();
    });
  }

  app.delete('/:id', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    await withTx(db, async (client) => {
      const res = await client.query('DELETE FROM emergency_access WHERE id = $1 AND (grantor_id = $2 OR grantee_id = $2)', [id, userId]);
      if (!res.rowCount) throw notFound('Emergency access not found');
      await audit(client, req, 'emergency.revoked', id);
    });
    return reply.status(204).send();
  });

  /** Read-only view of the grantor's personal vault (ciphertext + sealed key). */
  app.get('/:id/vault', async (req): Promise<EmergencyVault> => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    return withTx(db, async (client) => {
      const g = await load(client, id);
      if (g.grantee_id !== userId) throw notFound('Emergency access not found');
      if (g.status !== 'recovery_approved' || !g.key_sealed) throw forbidden('Emergency access has not been granted');
      const grantor = await userById(client, g.grantor_id);
      const items = await client.query<ItemRow>('SELECT * FROM items WHERE user_id = $1 AND deleted_at IS NULL ORDER BY created_at', [g.grantor_id]);
      await audit(client, req, 'emergency.vault_accessed', id, { grantor: grantor.email });
      return { grantorEmail: grantor.email, keySealed: g.key_sealed, items: items.rows.map(toItem) };
    });
  });
}
