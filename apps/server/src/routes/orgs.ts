import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  acceptInviteRequest,
  collectionCreate,
  collectionUpsert,
  confirmAuthRequest,
  confirmMemberRequest,
  createOrgRequest,
  groupUpsert,
  inviteRequest,
  orgItemCreate,
  orgItemUpdate,
  renameOrgRequest,
  shareItemRequest,
  updateMemberRequest,
  type InvitePreview,
  type OrgCollection,
  type OrgGroup,
  type OrgMember,
  type Permission,
} from '@enclavier/shared';
import { requireAuth } from '../app';
import { recordAudit, type AuditInput } from '../audit';
import { withOrgTx, type Queryable } from '../db';
import { badRequest, conflict, forbidden, notFound, parse, unauthorized } from '../errors';
import { inviteEmail } from '../mail';
import {
  collectionPermissions,
  countOwners,
  loadMembership,
  requireActiveMember,
  requireAdmin,
  requireCollection,
  requireOwner,
  type Membership,
} from '../orgs/access';
import { newRefreshToken, sha256, verifyAuthSecret } from '../security';
import { toItem, type ItemRow } from './vault';

const orgParam = z.object({ orgId: z.string().uuid() });
const memberParam = orgParam.extend({ memberId: z.string().uuid() });
const groupParam = orgParam.extend({ groupId: z.string().uuid() });
const collectionParam = orgParam.extend({ collectionId: z.string().uuid() });
const itemParam = orgParam.extend({ itemId: z.string().uuid() });
const inviteParam = z.object({ orgId: z.string().uuid(), memberId: z.string().uuid() });
const tokenQuery = z.object({ token: z.string().min(20).max(100) });
const deleteQuery = z.object({ permanent: z.enum(['true', 'false']).default('false') });

function dedupe<T>(list: T[], key: (t: T) => string): T[] {
  return [...new Map(list.map((t) => [key(t), t])).values()];
}

async function replaceMemberAccess(
  client: Queryable,
  orgId: string,
  memberId: string,
  collections: { id: string; permission: Permission }[],
  groups: string[],
): Promise<void> {
  const cols = dedupe(collections, (c) => c.id);
  await client.query('DELETE FROM collection_access WHERE org_id = $1 AND member_id = $2', [orgId, memberId]);
  if (cols.length) {
    await client.query(
      `INSERT INTO collection_access (collection_id, org_id, member_id, permission)
       SELECT unnest($1::uuid[]), $2, $3, unnest($4::text[])`,
      [cols.map((c) => c.id), orgId, memberId, cols.map((c) => c.permission)],
    );
  }
  await client.query('DELETE FROM group_members WHERE org_id = $1 AND member_id = $2', [orgId, memberId]);
  const gs = [...new Set(groups)];
  if (gs.length) {
    await client.query('INSERT INTO group_members (group_id, member_id, org_id) SELECT unnest($1::uuid[]), $2, $3', [gs, memberId, orgId]);
  }
}

/** Owners are protected: only owners may create, modify or remove them, and the last one can't be removed. */
async function assertCanManageMember(client: Queryable, actor: Membership, target: { id: string; role: string }, nextRole?: string) {
  if ((target.role === 'owner' || nextRole === 'owner') && actor.role !== 'owner') {
    throw forbidden('Only owners can manage owners');
  }
  if (target.role === 'owner' && nextRole !== 'owner' && (await countOwners(client, actor.orgId)) <= 1) {
    throw badRequest('An organization must keep at least one owner');
  }
}

async function loadTarget(client: Queryable, orgId: string, memberId: string) {
  const { rows } = await client.query(
    'SELECT id, user_id, email, role, status, revoked_at FROM org_members WHERE org_id = $1 AND id = $2',
    [orgId, memberId],
  );
  if (!rows[0]) throw notFound('Member not found');
  return rows[0] as { id: string; user_id: string | null; email: string; role: string; status: string; revoked_at: Date | null };
}

export async function orgRoutes(app: FastifyInstance): Promise<void> {
  const { db, config, mailer } = app;

  const audit = (client: Queryable, req: FastifyRequest, orgId: string, input: Omit<AuditInput, 'userId' | 'orgId'>) =>
    recordAudit(client, req, { ...input, orgId, userId: req.auth?.userId ?? null });

  async function sendInvite(orgId: string, memberId: string, email: string, token: string, orgName: string, inviterName: string) {
    const link = `${config.PUBLIC_URL.replace(/\/$/, '')}/accept-invite?org=${orgId}&member=${memberId}&token=${token}&email=${encodeURIComponent(email)}`;
    try {
      await mailer.send({ to: email, ...inviteEmail({ orgName, inviterName, link, expiresDays: config.INVITE_TTL_DAYS, email }) });
    } catch (err) {
      app.log.error({ err, email }, 'Failed to send invitation e-mail');
    }
  }

  // ---- public invitation endpoints -------------------------------------------

  app.get('/invites/:orgId/:memberId', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req): Promise<InvitePreview> => {
    const { orgId, memberId } = parse(inviteParam, req.params);
    const { token } = parse(tokenQuery, req.query);
    return withOrgTx(db, { orgId, userId: '' }, async (client) => {
      const { rows } = await client.query(
        `SELECT m.email, m.invite_token_hash, m.invite_expires_at, o.name AS org_name, u.name AS inviter_name
           FROM org_members m
           JOIN organizations o ON o.id = m.org_id
           LEFT JOIN users u ON u.id = m.invited_by
          WHERE m.org_id = $1 AND m.id = $2 AND m.status = 'invited'`,
        [orgId, memberId],
      );
      const r = rows[0];
      if (!r || !r.invite_token_hash || !sha256(token).equals(r.invite_token_hash) || r.invite_expires_at < new Date()) {
        throw notFound('This invitation is invalid or has expired');
      }
      return { orgName: r.org_name, email: r.email, inviterName: r.inviter_name };
    });
  });

  app.post('/invites/accept', { preHandler: app.authenticate, config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req) => {
    const { userId } = requireAuth(req);
    const body = parse(acceptInviteRequest, req.body);
    return withOrgTx(db, { orgId: body.orgId, userId }, async (client) => {
      const user = (await client.query<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId])).rows[0]!;
      const { rows } = await client.query(
        `SELECT id, email, invite_token_hash, invite_expires_at FROM org_members
          WHERE org_id = $1 AND id = $2 AND status = 'invited' FOR UPDATE`,
        [body.orgId, body.memberId],
      );
      const r = rows[0];
      if (!r || !r.invite_token_hash || !sha256(body.token).equals(r.invite_token_hash) || r.invite_expires_at < new Date()) {
        throw notFound('This invitation is invalid or has expired');
      }
      if (r.email !== user.email) throw forbidden(`This invitation was sent to ${r.email}. Sign in with that account to accept it.`);
      const existing = await client.query('SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2', [body.orgId, userId]);
      if (existing.rowCount) throw conflict('You are already a member of this organization');
      await client.query(
        `UPDATE org_members SET user_id = $3, status = 'accepted', invite_token_hash = NULL, invite_expires_at = NULL, updated_at = now()
          WHERE org_id = $1 AND id = $2`,
        [body.orgId, body.memberId, userId],
      );
      await audit(client, req, body.orgId, { action: 'member.accepted', targetType: 'member', targetId: body.memberId });
      return { status: 'accepted' as const };
    });
  });

  // ---- everything below requires authentication -------------------------------

  app.register(async (scoped) => {
    scoped.addHook('preHandler', app.authenticate);

    // ---- organization ---------------------------------------------------------

    scoped.post('/orgs', async (req, reply) => {
      const { userId } = requireAuth(req);
      const body = parse(createOrgRequest, req.body);
      const org = await withOrgTx(db, { orgId: body.id, userId }, async (client) => {
        const user = (await client.query<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId])).rows[0]!;
        await client.query('INSERT INTO organizations (id, name) VALUES ($1, $2)', [body.id, body.name]);
        const memberId = randomUUID();
        await client.query(
          `INSERT INTO org_members (id, org_id, user_id, email, role, status, protected_org_key)
           VALUES ($1, $2, $3, $4, 'owner', 'confirmed', $5)`,
          [memberId, body.id, userId, user.email, body.protectedOrgKey],
        );
        await client.query('INSERT INTO collections (id, org_id, name) VALUES ($1, $2, $3)', [
          body.defaultCollection.id,
          body.id,
          body.defaultCollection.name,
        ]);
        await audit(client, req, body.id, { action: 'org.created', targetType: 'org', targetId: body.id, metadata: { name: body.name } });
        return { id: body.id, name: body.name, memberId };
      });
      return reply.status(201).send(org);
    });

    scoped.patch('/orgs/:orgId', async (req) => {
      const { userId } = requireAuth(req);
      const { orgId } = parse(orgParam, req.params);
      const { name } = parse(renameOrgRequest, req.body);
      return withOrgTx(db, { orgId, userId }, async (client) => {
        await requireAdmin(client, orgId, userId);
        await client.query('UPDATE organizations SET name = $2, updated_at = now() WHERE id = $1', [orgId, name]);
        await audit(client, req, orgId, { action: 'org.updated', targetType: 'org', targetId: orgId, metadata: { name } });
        return { id: orgId, name };
      });
    });

    scoped.post('/orgs/:orgId/delete', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId } = parse(orgParam, req.params);
      const { authHash } = parse(confirmAuthRequest, req.body);
      await withOrgTx(db, { orgId, userId }, async (client) => {
        await requireOwner(client, orgId, userId);
        const { rows } = await client.query<{ auth_hash: string }>('SELECT auth_hash FROM users WHERE id = $1', [userId]);
        if (!(await verifyAuthSecret(authHash, rows[0]!.auth_hash))) throw unauthorized('Master password is incorrect');
        await client.query('DELETE FROM organizations WHERE id = $1', [orgId]);
        await audit(client, req, orgId, { action: 'org.deleted', targetType: 'org', targetId: orgId });
      });
      return reply.status(204).send();
    });

    scoped.post('/orgs/:orgId/leave', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId } = parse(orgParam, req.params);
      await withOrgTx(db, { orgId, userId }, async (client) => {
        const m = await loadMembership(client, orgId, userId);
        if (m.role === 'owner' && !m.revoked && (await countOwners(client, orgId)) <= 1) {
          throw badRequest('You are the last owner. Transfer ownership or delete the organization instead.');
        }
        await client.query('DELETE FROM org_members WHERE id = $1', [m.id]);
        await audit(client, req, orgId, { action: 'member.left', targetType: 'member', targetId: m.id });
      });
      return reply.status(204).send();
    });

    // ---- members --------------------------------------------------------------

    scoped.get('/orgs/:orgId/members', async (req): Promise<OrgMember[]> => {
      const { userId } = requireAuth(req);
      const { orgId } = parse(orgParam, req.params);
      return withOrgTx(db, { orgId, userId }, async (client) => {
        await requireAdmin(client, orgId, userId);
        const { rows } = await client.query(
          `SELECT m.*, u.name AS user_name, u.public_key,
                  EXISTS (SELECT 1 FROM sso_identities si WHERE si.org_id = m.org_id AND si.user_id = m.user_id) AS sso_linked,
                  (u.totp_enabled_at IS NOT NULL OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)) AS two_factor,
                  coalesce((SELECT array_agg(gm.group_id) FROM group_members gm WHERE gm.member_id = m.id), '{}') AS group_ids,
                  coalesce((SELECT json_agg(json_build_object('id', ca.collection_id, 'permission', ca.permission))
                              FROM collection_access ca WHERE ca.member_id = m.id), '[]') AS collection_grants
             FROM org_members m
             LEFT JOIN users u ON u.id = m.user_id
            WHERE m.org_id = $1
            ORDER BY m.created_at`,
          [orgId],
        );
        return rows.map((r) => ({
          id: r.id,
          userId: r.user_id,
          email: r.email,
          name: r.user_name ?? r.display_name,
          role: r.role,
          status: r.status,
          revoked: !!r.revoked_at,
          publicKey: r.status === 'invited' ? null : r.public_key,
          inviteExpiresAt: r.invite_expires_at?.toISOString() ?? null,
          twoFactorEnabled: !!r.two_factor,
          recoveryEnrolled: !!r.recovery_key,
          groups: r.group_ids,
          collections: r.collection_grants,
          createdAt: r.created_at.toISOString(),
          scimManaged: !!r.external_id,
          ssoLinked: !!r.sso_linked,
        }));
      });
    });

    scoped.post('/orgs/:orgId/members/invite', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req) => {
      const { userId } = requireAuth(req);
      const { orgId } = parse(orgParam, req.params);
      const body = parse(inviteRequest, req.body);
      const outbox: { memberId: string; email: string; token: string }[] = [];
      const skipped: string[] = [];
      const { orgName, inviterName } = await withOrgTx(db, { orgId, userId }, async (client) => {
        const actor = await requireAdmin(client, orgId, userId);
        if (body.role === 'owner' && actor.role !== 'owner') throw forbidden('Only owners can invite owners');
        for (const email of [...new Set(body.emails)]) {
          const exists = await client.query('SELECT 1 FROM org_members WHERE org_id = $1 AND email = $2', [orgId, email]);
          if (exists.rowCount) {
            skipped.push(email);
            continue;
          }
          const memberId = randomUUID();
          const token = newRefreshToken();
          await client.query(
            `INSERT INTO org_members (id, org_id, email, role, status, invite_token_hash, invite_expires_at, invited_by)
             VALUES ($1, $2, $3, $4, 'invited', $5, now() + make_interval(days => $6), $7)`,
            [memberId, orgId, email, body.role, sha256(token), config.INVITE_TTL_DAYS, userId],
          );
          await replaceMemberAccess(client, orgId, memberId, body.collections, body.groups);
          await audit(client, req, orgId, { action: 'member.invited', targetType: 'member', targetId: memberId, metadata: { email, role: body.role } });
          outbox.push({ memberId, email, token });
        }
        const org = (await client.query<{ name: string }>('SELECT name FROM organizations WHERE id = $1', [orgId])).rows[0]!;
        const me = (await client.query<{ name: string }>('SELECT name FROM users WHERE id = $1', [userId])).rows[0]!;
        return { orgName: org.name, inviterName: me.name };
      });
      // Send only after commit, so no one receives a link to a rolled-back invitation.
      await Promise.all(outbox.map((o) => sendInvite(orgId, o.memberId, o.email, o.token, orgName, inviterName)));
      return { invited: outbox.map((o) => o.email), skipped };
    });

    scoped.post('/orgs/:orgId/members/:memberId/reinvite', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId, memberId } = parse(memberParam, req.params);
      const token = newRefreshToken();
      const info = await withOrgTx(db, { orgId, userId }, async (client) => {
        await requireAdmin(client, orgId, userId);
        const target = await loadTarget(client, orgId, memberId);
        if (target.status !== 'invited') throw badRequest('This member has already accepted the invitation');
        await client.query(
          `UPDATE org_members SET invite_token_hash = $3, invite_expires_at = now() + make_interval(days => $4), invited_by = $5, updated_at = now()
            WHERE org_id = $1 AND id = $2`,
          [orgId, memberId, sha256(token), config.INVITE_TTL_DAYS, userId],
        );
        await audit(client, req, orgId, { action: 'member.reinvited', targetType: 'member', targetId: memberId });
        const org = (await client.query<{ name: string }>('SELECT name FROM organizations WHERE id = $1', [orgId])).rows[0]!;
        const me = (await client.query<{ name: string }>('SELECT name FROM users WHERE id = $1', [userId])).rows[0]!;
        return { email: target.email, orgName: org.name, inviterName: me.name };
      });
      await sendInvite(orgId, memberId, info.email, token, info.orgName, info.inviterName);
      return reply.status(204).send();
    });

    /** The admin's client seals the org key to the member's public key; the server only stores the sealed box. */
    scoped.post('/orgs/:orgId/members/:memberId/confirm', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId, memberId } = parse(memberParam, req.params);
      const { protectedOrgKey } = parse(confirmMemberRequest, req.body);
      await withOrgTx(db, { orgId, userId }, async (client) => {
        const actor = await requireAdmin(client, orgId, userId);
        const target = await loadTarget(client, orgId, memberId);
        if (target.status !== 'accepted') throw badRequest('Only members who accepted their invitation can be confirmed');
        if (target.revoked_at) throw badRequest('Restore this member before confirming');
        if (target.role === 'owner' && actor.role !== 'owner') throw forbidden('Only owners can confirm owners');
        await client.query(
          `UPDATE org_members SET status = 'confirmed', protected_org_key = $3, updated_at = now() WHERE org_id = $1 AND id = $2`,
          [orgId, memberId, protectedOrgKey],
        );
        await audit(client, req, orgId, { action: 'member.confirmed', targetType: 'member', targetId: memberId, metadata: { email: target.email } });
      });
      return reply.status(204).send();
    });

    scoped.put('/orgs/:orgId/members/:memberId', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId, memberId } = parse(memberParam, req.params);
      const body = parse(updateMemberRequest, req.body);
      await withOrgTx(db, { orgId, userId }, async (client) => {
        const actor = await requireAdmin(client, orgId, userId);
        const target = await loadTarget(client, orgId, memberId);
        await assertCanManageMember(client, actor, target, body.role);
        await client.query('UPDATE org_members SET role = $3, updated_at = now() WHERE org_id = $1 AND id = $2', [orgId, memberId, body.role]);
        await replaceMemberAccess(client, orgId, memberId, body.collections, body.groups);
        await audit(client, req, orgId, {
          action: 'member.updated',
          targetType: 'member',
          targetId: memberId,
          metadata: { email: target.email, role: body.role, collections: body.collections.length, groups: body.groups.length },
        });
      });
      return reply.status(204).send();
    });

    for (const action of ['revoke', 'restore'] as const) {
      scoped.post(`/orgs/:orgId/members/:memberId/${action}`, async (req, reply) => {
        const { userId } = requireAuth(req);
        const { orgId, memberId } = parse(memberParam, req.params);
        await withOrgTx(db, { orgId, userId }, async (client) => {
          const actor = await requireAdmin(client, orgId, userId);
          if (actor.id === memberId) throw badRequest('You cannot change your own access');
          const target = await loadTarget(client, orgId, memberId);
          if (action === 'revoke') await assertCanManageMember(client, actor, target);
          else if (target.role === 'owner' && actor.role !== 'owner') throw forbidden('Only owners can manage owners');
          await client.query(
            `UPDATE org_members SET revoked_at = ${action === 'revoke' ? 'now()' : 'NULL'}, updated_at = now() WHERE org_id = $1 AND id = $2`,
            [orgId, memberId],
          );
          await audit(client, req, orgId, {
            action: action === 'revoke' ? 'member.revoked' : 'member.restored',
            targetType: 'member',
            targetId: memberId,
            metadata: { email: target.email },
          });
        });
        return reply.status(204).send();
      });
    }

    scoped.delete('/orgs/:orgId/members/:memberId', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId, memberId } = parse(memberParam, req.params);
      await withOrgTx(db, { orgId, userId }, async (client) => {
        const actor = await requireAdmin(client, orgId, userId);
        if (actor.id === memberId) throw badRequest('Use "Leave organization" to remove yourself');
        const target = await loadTarget(client, orgId, memberId);
        await assertCanManageMember(client, actor, target);
        await client.query('DELETE FROM org_members WHERE org_id = $1 AND id = $2', [orgId, memberId]);
        await audit(client, req, orgId, { action: 'member.removed', targetType: 'member', targetId: memberId, metadata: { email: target.email } });
      });
      return reply.status(204).send();
    });

    // ---- groups ---------------------------------------------------------------

    scoped.get('/orgs/:orgId/groups', async (req): Promise<OrgGroup[]> => {
      const { userId } = requireAuth(req);
      const { orgId } = parse(orgParam, req.params);
      return withOrgTx(db, { orgId, userId }, async (client) => {
        await requireAdmin(client, orgId, userId);
        const { rows } = await client.query(
          `SELECT g.id, g.name, g.external_id,
                  coalesce((SELECT array_agg(gm.member_id) FROM group_members gm WHERE gm.group_id = g.id), '{}') AS member_ids,
                  coalesce((SELECT json_agg(json_build_object('id', ca.collection_id, 'permission', ca.permission))
                              FROM collection_access ca WHERE ca.group_id = g.id), '[]') AS collection_grants
             FROM groups g WHERE g.org_id = $1 ORDER BY g.name`,
          [orgId],
        );
        return rows.map((r) => ({ id: r.id, name: r.name, memberIds: r.member_ids, collections: r.collection_grants, externalId: r.external_id }));
      });
    });

    async function writeGroup(client: Queryable, orgId: string, groupId: string, body: z.infer<typeof groupUpsert>) {
      await client.query('DELETE FROM collection_access WHERE org_id = $1 AND group_id = $2', [orgId, groupId]);
      const cols = dedupe(body.collections, (c) => c.id);
      if (cols.length) {
        await client.query(
          `INSERT INTO collection_access (collection_id, org_id, group_id, permission)
           SELECT unnest($1::uuid[]), $2, $3, unnest($4::text[])`,
          [cols.map((c) => c.id), orgId, groupId, cols.map((c) => c.permission)],
        );
      }
      await client.query('DELETE FROM group_members WHERE org_id = $1 AND group_id = $2', [orgId, groupId]);
      const members = [...new Set(body.memberIds)];
      if (members.length) {
        await client.query('INSERT INTO group_members (group_id, member_id, org_id) SELECT $1, unnest($2::uuid[]), $3', [groupId, members, orgId]);
      }
    }

    scoped.post('/orgs/:orgId/groups', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId } = parse(orgParam, req.params);
      const body = parse(groupUpsert, req.body);
      const id = randomUUID();
      await withOrgTx(db, { orgId, userId }, async (client) => {
        await requireAdmin(client, orgId, userId);
        await client.query('INSERT INTO groups (id, org_id, name, external_id) VALUES ($1, $2, $3, $4)', [id, orgId, body.name, body.externalId || null]);
        await writeGroup(client, orgId, id, body);
        await audit(client, req, orgId, { action: 'group.created', targetType: 'group', targetId: id, metadata: { name: body.name } });
      });
      return reply.status(201).send({ id });
    });

    scoped.put('/orgs/:orgId/groups/:groupId', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId, groupId } = parse(groupParam, req.params);
      const body = parse(groupUpsert, req.body);
      await withOrgTx(db, { orgId, userId }, async (client) => {
        await requireAdmin(client, orgId, userId);
        const res = await client.query('UPDATE groups SET name = $3, external_id = $4 WHERE org_id = $1 AND id = $2', [
          orgId,
          groupId,
          body.name,
          body.externalId || null,
        ]);
        if (!res.rowCount) throw notFound('Group not found');
        await writeGroup(client, orgId, groupId, body);
        await audit(client, req, orgId, { action: 'group.updated', targetType: 'group', targetId: groupId, metadata: { name: body.name } });
      });
      return reply.status(204).send();
    });

    scoped.delete('/orgs/:orgId/groups/:groupId', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId, groupId } = parse(groupParam, req.params);
      await withOrgTx(db, { orgId, userId }, async (client) => {
        await requireAdmin(client, orgId, userId);
        const res = await client.query('DELETE FROM groups WHERE org_id = $1 AND id = $2', [orgId, groupId]);
        if (!res.rowCount) throw notFound('Group not found');
        await audit(client, req, orgId, { action: 'group.deleted', targetType: 'group', targetId: groupId });
      });
      return reply.status(204).send();
    });

    // ---- collections ----------------------------------------------------------

    scoped.get('/orgs/:orgId/collections', async (req): Promise<OrgCollection[]> => {
      const { userId } = requireAuth(req);
      const { orgId } = parse(orgParam, req.params);
      return withOrgTx(db, { orgId, userId }, async (client) => {
        const m = await requireActiveMember(client, orgId, userId);
        const perms = await collectionPermissions(client, m);
        // Access lists are visible to admins and to members who manage the collection.
        const manageable = [...perms].filter(([, p]) => p === 'manage').map(([id]) => id);
        const { rows } = await client.query(
          `SELECT c.id, c.name,
                  (SELECT count(*) FROM items i WHERE i.collection_id = c.id AND i.deleted_at IS NULL) AS item_count,
                  coalesce((SELECT json_agg(json_build_object('memberId', ca.member_id, 'permission', ca.permission))
                              FROM collection_access ca WHERE ca.collection_id = c.id AND ca.member_id IS NOT NULL), '[]') AS members,
                  coalesce((SELECT json_agg(json_build_object('groupId', ca.group_id, 'permission', ca.permission))
                              FROM collection_access ca WHERE ca.collection_id = c.id AND ca.group_id IS NOT NULL), '[]') AS groups
             FROM collections c WHERE c.org_id = $1 AND c.id = ANY($2::uuid[]) ORDER BY c.created_at`,
          [orgId, manageable],
        );
        return rows.map((r) => ({ id: r.id, name: r.name, itemCount: Number(r.item_count), members: r.members, groups: r.groups }));
      });
    });

    async function writeCollectionAccess(client: Queryable, orgId: string, collectionId: string, body: z.infer<typeof collectionUpsert>) {
      await client.query('DELETE FROM collection_access WHERE org_id = $1 AND collection_id = $2', [orgId, collectionId]);
      const members = dedupe(body.members, (m) => m.memberId);
      const groups = dedupe(body.groups, (g) => g.groupId);
      if (members.length) {
        await client.query(
          `INSERT INTO collection_access (collection_id, org_id, member_id, permission)
           SELECT $1, $2, unnest($3::uuid[]), unnest($4::text[])`,
          [collectionId, orgId, members.map((m) => m.memberId), members.map((m) => m.permission)],
        );
      }
      if (groups.length) {
        await client.query(
          `INSERT INTO collection_access (collection_id, org_id, group_id, permission)
           SELECT $1, $2, unnest($3::uuid[]), unnest($4::text[])`,
          [collectionId, orgId, groups.map((g) => g.groupId), groups.map((g) => g.permission)],
        );
      }
    }

    scoped.post('/orgs/:orgId/collections', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId } = parse(orgParam, req.params);
      const body = parse(collectionCreate, req.body);
      await withOrgTx(db, { orgId, userId }, async (client) => {
        await requireAdmin(client, orgId, userId);
        await client.query('INSERT INTO collections (id, org_id, name) VALUES ($1, $2, $3)', [body.id, orgId, body.name]);
        await writeCollectionAccess(client, orgId, body.id, body);
        await audit(client, req, orgId, { action: 'collection.created', targetType: 'collection', targetId: body.id });
      });
      return reply.status(201).send({ id: body.id });
    });

    scoped.put('/orgs/:orgId/collections/:collectionId', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId, collectionId } = parse(collectionParam, req.params);
      const body = parse(collectionUpsert, req.body);
      await withOrgTx(db, { orgId, userId }, async (client) => {
        const m = await requireActiveMember(client, orgId, userId);
        await requireCollection(client, m, collectionId, 'manage');
        await client.query('UPDATE collections SET name = $3, revision_date = now() WHERE org_id = $1 AND id = $2', [orgId, collectionId, body.name]);
        await writeCollectionAccess(client, orgId, collectionId, body);
        await audit(client, req, orgId, {
          action: 'collection.updated',
          targetType: 'collection',
          targetId: collectionId,
          metadata: { members: body.members.length, groups: body.groups.length },
        });
      });
      return reply.status(204).send();
    });

    scoped.delete('/orgs/:orgId/collections/:collectionId', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId, collectionId } = parse(collectionParam, req.params);
      await withOrgTx(db, { orgId, userId }, async (client) => {
        await requireAdmin(client, orgId, userId);
        const res = await client.query('DELETE FROM collections WHERE org_id = $1 AND id = $2', [orgId, collectionId]);
        if (!res.rowCount) throw notFound('Collection not found');
        await audit(client, req, orgId, { action: 'collection.deleted', targetType: 'collection', targetId: collectionId });
      });
      return reply.status(204).send();
    });

    // ---- organization items ---------------------------------------------------

    async function loadOrgItem(client: Queryable, orgId: string, itemId: string): Promise<ItemRow> {
      const { rows } = await client.query<ItemRow>('SELECT * FROM items WHERE org_id = $1 AND id = $2', [orgId, itemId]);
      if (!rows[0]) throw notFound('Item not found');
      return rows[0];
    }

    scoped.post('/orgs/:orgId/items', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId } = parse(orgParam, req.params);
      const body = parse(orgItemCreate, req.body);
      const item = await withOrgTx(db, { orgId, userId }, async (client) => {
        const m = await requireActiveMember(client, orgId, userId);
        await requireCollection(client, m, body.collectionId, 'edit');
        const { rows } = await client.query<ItemRow>(
          `INSERT INTO items (id, org_id, collection_id, key, data) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
          [body.id, orgId, body.collectionId, body.key, body.data],
        );
        await audit(client, req, orgId, { action: 'item.created', targetType: 'item', targetId: body.id, metadata: { collectionId: body.collectionId } });
        return toItem(rows[0]!);
      });
      return reply.status(201).send(item);
    });

    scoped.put('/orgs/:orgId/items/:itemId', async (req) => {
      const { userId } = requireAuth(req);
      const { orgId, itemId } = parse(itemParam, req.params);
      const body = parse(orgItemUpdate, req.body);
      return withOrgTx(db, { orgId, userId }, async (client) => {
        const m = await requireActiveMember(client, orgId, userId);
        const current = await loadOrgItem(client, orgId, itemId);
        await requireCollection(client, m, current.collection_id!, 'edit');
        if (body.collectionId !== current.collection_id) await requireCollection(client, m, body.collectionId, 'edit');
        const { rows } = await client.query<ItemRow>(
          `UPDATE items SET collection_id = $3, data = $4, revision = revision + 1, revision_date = now()
            WHERE org_id = $1 AND id = $2 AND revision = $5 RETURNING *`,
          [orgId, itemId, body.collectionId, body.data, body.revision],
        );
        if (!rows[0]) throw conflict('Item was changed by someone else. Sync and try again.');
        await audit(client, req, orgId, { action: 'item.updated', targetType: 'item', targetId: itemId, metadata: { collectionId: body.collectionId } });
        return toItem(rows[0]);
      });
    });

    scoped.post('/orgs/:orgId/items/:itemId/restore', async (req) => {
      const { userId } = requireAuth(req);
      const { orgId, itemId } = parse(itemParam, req.params);
      return withOrgTx(db, { orgId, userId }, async (client) => {
        const m = await requireActiveMember(client, orgId, userId);
        const current = await loadOrgItem(client, orgId, itemId);
        await requireCollection(client, m, current.collection_id!, 'edit');
        const { rows } = await client.query<ItemRow>(
          `UPDATE items SET deleted_at = NULL, revision = revision + 1, revision_date = now()
            WHERE org_id = $1 AND id = $2 AND deleted_at IS NOT NULL RETURNING *`,
          [orgId, itemId],
        );
        if (!rows[0]) throw notFound('Item not in trash');
        await audit(client, req, orgId, { action: 'item.restored', targetType: 'item', targetId: itemId });
        return toItem(rows[0]);
      });
    });

    scoped.delete('/orgs/:orgId/items/:itemId', async (req, reply) => {
      const { userId } = requireAuth(req);
      const { orgId, itemId } = parse(itemParam, req.params);
      const permanent = parse(deleteQuery, req.query).permanent === 'true';
      await withOrgTx(db, { orgId, userId }, async (client) => {
        const m = await requireActiveMember(client, orgId, userId);
        const current = await loadOrgItem(client, orgId, itemId);
        // Trashing needs edit; permanent deletion of shared data needs manage.
        await requireCollection(client, m, current.collection_id!, permanent ? 'manage' : 'edit');
        const res = permanent
          ? await client.query('DELETE FROM items WHERE org_id = $1 AND id = $2', [orgId, itemId])
          : await client.query(
              `UPDATE items SET deleted_at = now(), revision = revision + 1, revision_date = now()
                WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL`,
              [orgId, itemId],
            );
        if (!res.rowCount) throw notFound('Item not found');
        await audit(client, req, orgId, { action: permanent ? 'item.deleted' : 'item.trashed', targetType: 'item', targetId: itemId });
      });
      return reply.status(204).send();
    });

    /** Moves a personal item into an org collection. The client re-wraps only the item key. */
    scoped.post('/items/:itemId/share', async (req) => {
      const { userId } = requireAuth(req);
      const { itemId } = parse(z.object({ itemId: z.string().uuid() }), req.params);
      const body = parse(shareItemRequest, req.body);
      return withOrgTx(db, { orgId: body.orgId, userId }, async (client) => {
        const m = await requireActiveMember(client, body.orgId, userId);
        await requireCollection(client, m, body.collectionId, 'edit');
        const { rows } = await client.query<ItemRow>(
          `UPDATE items SET user_id = NULL, folder_id = NULL, org_id = $3, collection_id = $4, key = $5,
                  revision = revision + 1, revision_date = now()
            WHERE id = $1 AND user_id = $2 AND org_id IS NULL AND deleted_at IS NULL AND revision = $6
            RETURNING *`,
          [itemId, userId, body.orgId, body.collectionId, body.key, body.revision],
        );
        if (!rows[0]) throw conflict('Item not found or changed on another device. Sync and try again.');
        await audit(client, req, body.orgId, { action: 'item.shared', targetType: 'item', targetId: itemId, metadata: { collectionId: body.collectionId } });
        return toItem(rows[0]);
      });
    });
  });
}

