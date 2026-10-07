import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  deviceApprovalRequest,
  deviceApproveRequest,
  deviceTrustRequest,
  type AdminDeviceRequest,
  type TrustedDevice,
} from '@enclavier/shared';
import { requireAuth } from '../app';
import { recordAudit } from '../audit';
import { withOrgTx, withTx, type Queryable } from '../db';
import { badRequest, conflict, forbidden, notFound, parse } from '../errors';
import { loadPolicies, requireActiveMember, requireAdmin } from '../orgs/access';
import { notify } from '../twofactor';

const idParam = z.object({ id: z.string().uuid() });
const orgParam = z.object({ orgId: z.string().uuid() });
const orgDeviceParam = orgParam.extend({ id: z.string().uuid() });

interface DeviceRow {
  id: string;
  user_id: string;
  name: string;
  public_key: string;
  status: TrustedDevice['status'];
  protected_user_key: string | null;
  admin_org_id: string | null;
  approved_by: string | null;
  org_name: string | null;
  created_at: Date;
  trusted_at: Date | null;
  last_used_at: Date | null;
}

const SELECT = `SELECT d.*, o.name AS org_name FROM devices d LEFT JOIN organizations o ON o.id = d.admin_org_id`;

/**
 * The sealed user key is handed out only to collect a fresh approval (for 15
 * minutes). Afterwards a trusted device gets it solely through a new SSO
 * sign-in, so a stolen refresh token can't unlock a locked vault.
 */
function collectable(r: DeviceRow): boolean {
  return r.status === 'trusted' && !!r.approved_by && !!r.trusted_at && Date.now() - r.trusted_at.getTime() < 15 * 60_000;
}

function toDevice(r: DeviceRow, withKey = false): TrustedDevice {
  return {
    id: r.id,
    name: r.name,
    publicKey: r.public_key,
    status: r.status,
    adminApprovalOrg: r.admin_org_id ? { id: r.admin_org_id, name: r.org_name ?? '' } : null,
    createdAt: r.created_at.toISOString(),
    trustedAt: r.trusted_at?.toISOString() ?? null,
    lastUsedAt: r.last_used_at?.toISOString() ?? null,
    protectedUserKey: withKey ? r.protected_user_key : null,
  };
}

/** Pending requests expire after a day. */
const PENDING_FRESH = `(d.status <> 'pending' OR d.created_at > now() - interval '1 day')`;

export async function deviceRoutes(app: FastifyInstance): Promise<void> {
  const { db } = app;
  app.addHook('preHandler', app.authenticate);

  async function emailOf(client: Queryable, userId: string) {
    return (await client.query<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId])).rows[0]!.email;
  }

  async function ownDevice(client: Queryable, userId: string, id: string): Promise<DeviceRow> {
    const { rows } = await client.query<DeviceRow>(`${SELECT} WHERE d.id = $1 AND d.user_id = $2`, [id, userId]);
    if (!rows[0]) throw notFound('Device not found');
    return rows[0];
  }

  // ---- the user's own devices ------------------------------------------------------------

  app.get('/devices', async (req): Promise<TrustedDevice[]> => {
    const { userId } = requireAuth(req);
    const { rows } = await db.query<DeviceRow>(`${SELECT} WHERE d.user_id = $1 AND d.status <> 'denied' AND ${PENDING_FRESH} ORDER BY d.created_at DESC`, [userId]);
    return rows.map((r) => toDevice(r));
  });

  app.get('/devices/:id', async (req): Promise<TrustedDevice> => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    const d = await ownDevice(db, userId, id);
    return toDevice(d, collectable(d));
  });

  /** An unlocked device trusts itself: it seals the user key to its own key pair. */
  app.post('/devices/trust', async (req, reply) => {
    const { userId } = requireAuth(req);
    const body = parse(deviceTrustRequest, req.body);
    const email = await withTx(db, async (client) => {
      const existing = await client.query<{ user_id: string }>('SELECT user_id FROM devices WHERE id = $1', [body.id]);
      if (existing.rows[0] && existing.rows[0].user_id !== userId) throw conflict('Device id already in use');
      await client.query(
        `INSERT INTO devices (id, user_id, name, public_key, status, protected_user_key, trusted_at)
         VALUES ($1, $2, $3, $4, 'trusted', $5, now())
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, public_key = EXCLUDED.public_key, status = 'trusted',
           protected_user_key = EXCLUDED.protected_user_key, trusted_at = now(), admin_org_id = NULL`,
        [body.id, userId, body.name, body.publicKey, body.protectedUserKey],
      );
      await recordAudit(client, req, { userId, action: 'device.trusted', targetType: 'device', targetId: body.id, metadata: { name: body.name } });
      return emailOf(client, userId);
    });
    void notify(app, email, 'A device can now unlock your Enclavier vault with SSO', [
      `**${body.name}** was marked as a trusted device. After signing in with your organization's single sign-on it can open your vault without your master password.`,
      'If this was not you, remove it under Settings → Devices and change your master password.',
    ]);
    return reply.status(204).send();
  });

  /** A new device without the master password asks another device (or an admin) to release the key. */
  app.post('/devices/request', { config: { rateLimit: { max: 10, timeWindow: '10 minutes' } } }, async (req, reply) => {
    const { userId } = requireAuth(req);
    const body = parse(deviceApprovalRequest, req.body);
    const device = await withTx(db, async (client) => {
      const existing = await client.query<{ user_id: string; status: string }>('SELECT user_id, status FROM devices WHERE id = $1', [body.id]);
      if (existing.rows[0]) throw conflict('This device already has a request. Start a new one.');
      if (body.adminOrgId) {
        await withOrgTx(db, { orgId: body.adminOrgId, userId }, async (org) => {
          const m = await requireActiveMember(org, body.adminOrgId!, userId);
          const enrolled = await org.query('SELECT 1 FROM org_members WHERE id = $1 AND recovery_key IS NOT NULL', [m.id]);
          if (!enrolled.rowCount) throw badRequest('Admin approval needs account recovery enrollment in this organization');
        });
      }
      await client.query(
        `INSERT INTO devices (id, user_id, name, public_key, status, admin_org_id) VALUES ($1, $2, $3, $4, 'pending', $5)`,
        [body.id, userId, body.name, body.publicKey, body.adminOrgId ?? null],
      );
      await recordAudit(client, req, {
        userId,
        orgId: body.adminOrgId ?? null,
        action: 'device.approval_requested',
        targetType: 'device',
        targetId: body.id,
        metadata: { name: body.name, via: body.adminOrgId ? 'admin' : 'device' },
      });
      return ownDevice(client, userId, body.id);
    });
    return reply.status(201).send(toDevice(device));
  });

  /** Approval from one of the user's unlocked devices (it compared the fingerprint phrase). */
  app.post('/devices/:id/approve', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    const { protectedUserKey } = parse(deviceApproveRequest, req.body);
    const { email, name } = await withTx(db, async (client) => {
      const d = await ownDevice(client, userId, id);
      if (d.status !== 'pending') throw badRequest('This request was already handled');
      await client.query(
        `UPDATE devices SET status = 'trusted', protected_user_key = $2, trusted_at = now(), approved_by = $3 WHERE id = $1`,
        [id, protectedUserKey, userId],
      );
      await recordAudit(client, req, { userId, action: 'device.approved', targetType: 'device', targetId: id, metadata: { name: d.name, via: 'device' } });
      return { email: await emailOf(client, userId), name: d.name };
    });
    void notify(app, email, 'You approved a new device', [`**${name}** can now open your Enclavier vault after signing in with SSO.`]);
    return reply.status(204).send();
  });

  app.post('/devices/:id/deny', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    await withTx(db, async (client) => {
      const d = await ownDevice(client, userId, id);
      if (d.status !== 'pending') throw badRequest('This request was already handled');
      await client.query(`UPDATE devices SET status = 'denied' WHERE id = $1`, [id]);
      await recordAudit(client, req, { userId, action: 'device.denied', targetType: 'device', targetId: id, metadata: { name: d.name } });
    });
    return reply.status(204).send();
  });

  app.delete('/devices/:id', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    await withTx(db, async (client) => {
      const d = await ownDevice(client, userId, id);
      await client.query('DELETE FROM devices WHERE id = $1', [id]);
      await recordAudit(client, req, { userId, action: 'device.removed', targetType: 'device', targetId: id, metadata: { name: d.name } });
    });
    return reply.status(204).send();
  });

  // ---- admin approval (via the account recovery key) -----------------------------------------

  async function adminTarget(client: Queryable, orgId: string, actorId: string, deviceId: string) {
    const actor = await requireAdmin(client, orgId, actorId);
    if (!(await loadPolicies(client, orgId)).get('account_recovery')?.enabled) throw badRequest('Account recovery is not enabled');
    const { rows } = await client.query(
      `SELECT d.id, d.name, d.status, d.user_id, m.id AS member_id, m.role, m.recovery_key, u.email
         FROM devices d
         JOIN org_members m ON m.org_id = $1 AND m.user_id = d.user_id
         JOIN users u ON u.id = d.user_id
        WHERE d.id = $2 AND d.admin_org_id = $1 AND d.status = 'pending' AND d.created_at > now() - interval '1 day'`,
      [orgId, deviceId],
    );
    const t = rows[0];
    if (!t) throw notFound('Request not found or already handled');
    if (t.user_id === actorId) throw badRequest('Approve your own devices from another of your devices');
    if (t.role === 'owner' && actor.role !== 'owner') throw forbidden('Only owners can approve devices of owners');
    if (!t.recovery_key) throw badRequest('This member is not enrolled in account recovery');
    return t as { id: string; name: string; user_id: string; member_id: string; email: string };
  }

  app.get('/orgs/:orgId/device-requests', async (req): Promise<AdminDeviceRequest[]> => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    return withOrgTx(db, { orgId, userId }, async (client) => {
      await requireAdmin(client, orgId, userId);
      const { rows } = await client.query(
        `SELECT d.id, d.name AS device_name, d.public_key, d.created_at, m.id AS member_id, u.email, u.name
           FROM devices d
           JOIN org_members m ON m.org_id = $1 AND m.user_id = d.user_id
           JOIN users u ON u.id = d.user_id
          WHERE d.admin_org_id = $1 AND d.status = 'pending' AND d.created_at > now() - interval '1 day'
          ORDER BY d.created_at`,
        [orgId],
      );
      return rows.map((r) => ({
        id: r.id,
        memberId: r.member_id,
        email: r.email,
        name: r.name,
        deviceName: r.device_name,
        publicKey: r.public_key,
        createdAt: r.created_at.toISOString(),
      }));
    });
  });

  app.post('/orgs/:orgId/device-requests/:id/approve', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { userId } = requireAuth(req);
    const { orgId, id } = parse(orgDeviceParam, req.params);
    const { protectedUserKey } = parse(deviceApproveRequest, req.body);
    const t = await withOrgTx(db, { orgId, userId }, async (client) => {
      const target = await adminTarget(client, orgId, userId, id);
      await client.query(`UPDATE devices SET status = 'trusted', protected_user_key = $2, trusted_at = now(), approved_by = $3 WHERE id = $1`, [
        id,
        protectedUserKey,
        userId,
      ]);
      await recordAudit(client, req, {
        orgId,
        userId,
        action: 'device.approved',
        targetType: 'member',
        targetId: target.member_id,
        metadata: { email: target.email, device: target.name, via: 'admin' },
      });
      return target;
    });
    void notify(app, t.email, 'An administrator approved your new device', [
      `An administrator approved **${t.name}**. It can now open your Enclavier vault after signing in with SSO.`,
      'If you did not ask for this, contact your security team immediately.',
    ]);
    return reply.status(204).send();
  });

  app.post('/orgs/:orgId/device-requests/:id/deny', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { orgId, id } = parse(orgDeviceParam, req.params);
    await withOrgTx(db, { orgId, userId }, async (client) => {
      const target = await adminTarget(client, orgId, userId, id);
      await client.query(`UPDATE devices SET status = 'denied' WHERE id = $1`, [id]);
      await recordAudit(client, req, { orgId, userId, action: 'device.denied', targetType: 'member', targetId: target.member_id, metadata: { email: target.email, device: target.name } });
    });
    return reply.status(204).send();
  });
}
