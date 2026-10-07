import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  folderUpsert,
  itemCreate,
  itemUpdate,
  type CollectionSummary,
  type Folder,
  type Item,
  type OrgSummary,
  type SyncResponse,
} from '@enclavier/shared';
import { requireAuth } from '../app';
import { recordAudit } from '../audit';
import { withOrgTx, withTx, type Queryable } from '../db';
import { collectionPermissions, loadPolicies, policyBlock } from '../orgs/access';
import { policiesToDto } from './orgRecovery';
import { badRequest, conflict, notFound, parse } from '../errors';
import { toKeys, toProfile, USER_SELECT, type UserRow } from '../users';

const idParam = z.object({ id: z.string().uuid() });
const deleteQuery = z.object({ permanent: z.enum(['true', 'false']).default('false') });
const folderRename = folderUpsert.pick({ name: true });

export interface ItemRow {
  id: string;
  folder_id: string | null;
  org_id: string | null;
  collection_id: string | null;
  key: string;
  data: string;
  revision: number;
  created_at: Date;
  revision_date: Date;
  deleted_at: Date | null;
}

export const toItem = (r: ItemRow): Item => ({
  id: r.id,
  folderId: r.folder_id,
  orgId: r.org_id,
  collectionId: r.collection_id,
  key: r.key,
  data: r.data,
  revision: r.revision,
  createdAt: r.created_at.toISOString(),
  revisionDate: r.revision_date.toISOString(),
  deletedAt: r.deleted_at?.toISOString() ?? null,
});

const toFolder = (r: { id: string; name: string; revision_date: Date }): Folder => ({
  id: r.id,
  name: r.name,
  revisionDate: r.revision_date.toISOString(),
});

async function assertFolder(client: Queryable, userId: string, folderId: string | null): Promise<void> {
  if (!folderId) return;
  const { rowCount } = await client.query('SELECT 1 FROM folders WHERE id = $1 AND user_id = $2', [folderId, userId]);
  if (!rowCount) throw badRequest('Folder does not exist');
}

export async function vaultRoutes(app: FastifyInstance): Promise<void> {
  const { db } = app;
  app.addHook('preHandler', app.authenticate);

  app.get('/sync', async (req): Promise<SyncResponse> => {
    const { userId } = requireAuth(req);
    const [user, folders, items] = await Promise.all([
      db.query<UserRow>(`${USER_SELECT} WHERE u.id = $1`, [userId]),
      db.query('SELECT id, name, revision_date FROM folders WHERE user_id = $1 ORDER BY created_at', [userId]),
      db.query<ItemRow>('SELECT * FROM items WHERE user_id = $1 ORDER BY created_at', [userId]),
    ]);
    const u = user.rows[0]!;

    // Organizations: every membership is listed (so pending invites show up), but
    // collections and items only come from confirmed, non-revoked memberships.
    const memberships = await db.query(
      `SELECT m.id, m.org_id, m.role, m.status, m.revoked_at, m.protected_org_key, m.recovery_key, o.name, o.recovery_public_key
         FROM org_members m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = $1 ORDER BY o.name`,
      [userId],
    );
    const organizations: OrgSummary[] = [];
    const collections: CollectionSummary[] = [];
    const orgItems: Item[] = [];
    for (const m of memberships.rows) {
      if (m.revoked_at) continue;
      const { policies, blocked } = await withOrgTx(db, { orgId: m.org_id, userId }, async (client) => ({
        policies: policiesToDto(await loadPolicies(client, m.org_id)),
        blocked: await policyBlock(client, m.org_id, userId),
      }));
      const active = m.status === 'confirmed' && !blocked;
      organizations.push({
        id: m.org_id,
        name: m.name,
        role: m.role,
        status: m.status,
        memberId: m.id,
        // Withheld while a policy blocks access, so non-compliant devices hold no org key.
        protectedOrgKey: active ? m.protected_org_key : null,
        policies,
        recoveryPublicKey: policies.accountRecovery ? m.recovery_public_key : null,
        recoveryEnrolled: !!m.recovery_key,
        blockedByPolicy: m.status === 'confirmed' ? blocked : null,
      });
      if (!active) continue;
      await withOrgTx(db, { orgId: m.org_id, userId }, async (client) => {
        const perms = await collectionPermissions(client, {
          id: m.id, orgId: m.org_id, userId, email: u.email, role: m.role, status: m.status, revoked: false,
        });
        const ids = [...perms.keys()];
        if (!ids.length) return;
        const cols = await client.query('SELECT id, name FROM collections WHERE org_id = $1 AND id = ANY($2::uuid[])', [m.org_id, ids]);
        for (const c of cols.rows) collections.push({ id: c.id, orgId: m.org_id, name: c.name, permission: perms.get(c.id)! });
        const its = await client.query<ItemRow>('SELECT * FROM items WHERE org_id = $1 AND collection_id = ANY($2::uuid[])', [m.org_id, ids]);
        orgItems.push(...its.rows.map(toItem));
      });
    }

    return {
      profile: toProfile(u),
      keys: toKeys(u),
      folders: folders.rows.map(toFolder),
      items: [...items.rows.map(toItem), ...orgItems],
      organizations,
      collections,
      serverTime: new Date().toISOString(),
    };
  });

  // ---- folders ------------------------------------------------------------

  app.post('/folders', async (req, reply) => {
    const { userId } = requireAuth(req);
    const body = parse(folderUpsert, req.body);
    const folder = await withTx(db, async (client) => {
      const { rows } = await client.query(
        'INSERT INTO folders (id, user_id, name) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING RETURNING id, name, revision_date',
        [body.id, userId, body.name],
      );
      if (!rows[0]) throw conflict('Folder id already exists');
      await recordAudit(client, req, { userId, action: 'folder.created', targetType: 'folder', targetId: body.id });
      return toFolder(rows[0]);
    });
    return reply.status(201).send(folder);
  });

  app.put('/folders/:id', async (req) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    const { name } = parse(folderRename, req.body);
    return withTx(db, async (client) => {
      const { rows } = await client.query(
        'UPDATE folders SET name = $3, revision_date = now() WHERE id = $1 AND user_id = $2 RETURNING id, name, revision_date',
        [id, userId, name],
      );
      if (!rows[0]) throw notFound('Folder not found');
      await recordAudit(client, req, { userId, action: 'folder.updated', targetType: 'folder', targetId: id });
      return toFolder(rows[0]);
    });
  });

  app.delete('/folders/:id', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    await withTx(db, async (client) => {
      const res = await client.query('DELETE FROM folders WHERE id = $1 AND user_id = $2', [id, userId]);
      if (!res.rowCount) throw notFound('Folder not found');
      await recordAudit(client, req, { userId, action: 'folder.deleted', targetType: 'folder', targetId: id });
    });
    return reply.status(204).send();
  });

  // ---- items --------------------------------------------------------------

  app.post('/items', async (req, reply) => {
    const { userId } = requireAuth(req);
    const body = parse(itemCreate, req.body);
    const item = await withTx(db, async (client) => {
      await assertFolder(client, userId, body.folderId);
      const { rows } = await client.query<ItemRow>(
        `INSERT INTO items (id, user_id, folder_id, key, data) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (id) DO NOTHING RETURNING *`,
        [body.id, userId, body.folderId, body.key, body.data],
      );
      if (!rows[0]) throw conflict('Item id already exists');
      await recordAudit(client, req, { userId, action: 'item.created', targetType: 'item', targetId: body.id });
      return toItem(rows[0]);
    });
    return reply.status(201).send(item);
  });

  app.put('/items/:id', async (req) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    const body = parse(itemUpdate, req.body);
    return withTx(db, async (client) => {
      await assertFolder(client, userId, body.folderId);
      const { rows } = await client.query<ItemRow>(
        `UPDATE items SET folder_id = $3, data = $4, revision = revision + 1, revision_date = now()
          WHERE id = $1 AND user_id = $2 AND revision = $5 RETURNING *`,
        [id, userId, body.folderId, body.data, body.revision],
      );
      if (!rows[0]) {
        const exists = await client.query('SELECT 1 FROM items WHERE id = $1 AND user_id = $2', [id, userId]);
        throw exists.rowCount ? conflict('Item was changed on another device. Sync and try again.') : notFound('Item not found');
      }
      await recordAudit(client, req, { userId, action: 'item.updated', targetType: 'item', targetId: id });
      return toItem(rows[0]);
    });
  });

  app.post('/items/:id/restore', async (req) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    return withTx(db, async (client) => {
      const { rows } = await client.query<ItemRow>(
        `UPDATE items SET deleted_at = NULL, revision = revision + 1, revision_date = now()
          WHERE id = $1 AND user_id = $2 AND deleted_at IS NOT NULL RETURNING *`,
        [id, userId],
      );
      if (!rows[0]) throw notFound('Item not in trash');
      await recordAudit(client, req, { userId, action: 'item.restored', targetType: 'item', targetId: id });
      return toItem(rows[0]);
    });
  });

  app.delete('/items/:id', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { id } = parse(idParam, req.params);
    const permanent = parse(deleteQuery, req.query).permanent === 'true';
    await withTx(db, async (client) => {
      const res = permanent
        ? await client.query('DELETE FROM items WHERE id = $1 AND user_id = $2', [id, userId])
        : await client.query(
            `UPDATE items SET deleted_at = now(), revision = revision + 1, revision_date = now()
              WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
            [id, userId],
          );
      if (!res.rowCount) throw notFound('Item not found');
      await recordAudit(client, req, { userId, action: permanent ? 'item.deleted' : 'item.trashed', targetType: 'item', targetId: id });
    });
    return reply.status(204).send();
  });
}
