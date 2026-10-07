import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { changePasswordRequest, type AuditEvent, type Session } from '@enclavier/shared';
import { requireAuth } from '../app';
import { recordAudit } from '../audit';
import { withTx } from '../db';
import { badRequest, notFound, parse, unauthorized } from '../errors';
import { hashAuthSecret, verifyAuthSecret } from '../security';
import { findUser, toKeys, toProfile, type UserRow } from '../users';
import { issueEmailVerification, sendVerificationEmail } from '../twofactor';

const confirmRequest = z.object({ authHash: z.string().regex(/^[A-Za-z0-9_-]{43}$/) });
const idParam = z.object({ id: z.string().uuid() });
const eventsQuery = z.object({
  before: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

export async function accountRoutes(app: FastifyInstance): Promise<void> {
  const { db } = app;
  app.addHook('preHandler', app.authenticate);

  async function loadUser(id: string): Promise<UserRow> {
    const user = await findUser(db, 'id', id);
    if (!user) throw unauthorized();
    return user;
  }

  app.get('/me', async (req) => {
    const user = await loadUser(requireAuth(req).userId);
    return { profile: toProfile(user), keys: toKeys(user) };
  });

  // Master password change: the client re-wraps its user key; the vault is untouched.
  app.post('/password', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { userId, sessionId } = requireAuth(req);
    const body = parse(changePasswordRequest, req.body);
    const user = await loadUser(userId);
    if (!(await verifyAuthSecret(body.currentAuthHash, user.auth_hash))) {
      throw unauthorized('Current master password is incorrect');
    }
    const authHash = await hashAuthSecret(body.authHash);
    await withTx(db, async (client) => {
      await client.query(
        `UPDATE users SET auth_hash = $2, kdf = $3, salt = $4, protected_user_key = $5, force_password_change = false, updated_at = now()
          WHERE id = $1`,
        [userId, authHash, body.kdf, body.salt, body.protectedUserKey],
      );
      // Every other device must log in again with the new password.
      await client.query('UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL', [userId, sessionId]);
      await recordAudit(client, req, { userId, action: 'user.password_changed', targetType: 'user', targetId: userId });
    });
    return reply.status(204).send();
  });

  app.post('/verify-email/resend', { config: { rateLimit: { max: 3, timeWindow: '10 minutes' } } }, async (req, reply) => {
    const user = await loadUser(requireAuth(req).userId);
    if (user.email_verified_at) return reply.status(204).send();
    const link = await withTx(db, (client) => issueEmailVerification(client, app.config, user.id));
    await sendVerificationEmail(app, user.email, user.name, link);
    return reply.status(204).send();
  });

  app.get('/sessions', async (req): Promise<Session[]> => {
    const { userId, sessionId } = requireAuth(req);
    const { rows } = await db.query(
      `SELECT id, device_name, user_agent, ip, created_at, last_used_at FROM sessions
        WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY last_used_at DESC`,
      [userId],
    );
    return rows.map((r) => ({
      id: r.id,
      deviceName: r.device_name,
      userAgent: r.user_agent,
      ip: r.ip,
      createdAt: r.created_at.toISOString(),
      lastUsedAt: r.last_used_at.toISOString(),
      current: r.id === sessionId,
    }));
  });

  app.delete('/sessions/:id', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    await withTx(db, async (client) => {
      const res = await client.query('UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL', [id, userId]);
      if (!res.rowCount) throw notFound('Session not found');
      await recordAudit(client, req, { userId, action: 'session.revoked', targetType: 'session', targetId: id });
    });
    return reply.status(204).send();
  });

  app.get('/events', async (req): Promise<AuditEvent[]> => {
    const { userId } = requireAuth(req);
    const q = parse(eventsQuery, req.query);
    const { rows } = await db.query(
      `SELECT id, action, target_type, target_id, ip, user_agent, created_at FROM audit_events
        WHERE user_id = $1 AND ($2::bigint IS NULL OR id < $2) ORDER BY id DESC LIMIT $3`,
      [userId, q.before ?? null, q.limit],
    );
    return rows.map((r) => ({
      id: Number(r.id),
      action: r.action,
      targetType: r.target_type,
      targetId: r.target_id,
      ip: r.ip,
      userAgent: r.user_agent,
      createdAt: r.created_at.toISOString(),
    }));
  });

  /** Clients call this when the user exports their vault, so the export is on the audit trail. */
  app.post('/events/export', async (req, reply) => {
    const { userId } = requireAuth(req);
    await withTx(db, (client) => recordAudit(client, req, { userId, action: 'vault.exported', targetType: 'user', targetId: userId }));
    return reply.status(204).send();
  });

  app.post('/delete', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { userId } = requireAuth(req);
    const { authHash } = parse(confirmRequest, req.body);
    const user = await loadUser(userId);
    if (!(await verifyAuthSecret(authHash, user.auth_hash))) throw unauthorized('Master password is incorrect');
    const soleOwner = await db.query<{ name: string }>(
      `SELECT o.name FROM org_members m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = $1 AND m.role = 'owner' AND m.status = 'confirmed' AND m.revoked_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM org_members x WHERE x.org_id = m.org_id AND x.id <> m.id
                            AND x.role = 'owner' AND x.status = 'confirmed' AND x.revoked_at IS NULL)`,
      [userId],
    );
    if (soleOwner.rows[0]) {
      throw badRequest(`You are the only owner of "${soleOwner.rows[0].name}". Transfer ownership or delete the organization first.`);
    }
    await withTx(db, async (client) => {
      await client.query('DELETE FROM users WHERE id = $1', [userId]);
      await recordAudit(client, req, { userId, action: 'user.deleted', targetType: 'user', targetId: userId });
    });
    return reply.status(204).send();
  });
}
