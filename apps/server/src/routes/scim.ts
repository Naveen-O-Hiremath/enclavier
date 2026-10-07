import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type pg from 'pg';
import { recordAudit, type AuditAction } from '../audit';
import { withOrgTx, type Queryable } from '../db';
import { inviteEmail } from '../mail';
import { countOwners } from '../orgs/access';
import { newRefreshToken, sha256 } from '../security';

// SCIM 2.0 (RFC 7643 / 7644) for identity-provider provisioning: Okta, Entra ID,
// OneLogin, JumpCloud… A SCIM "User" is a membership of the token's organization.

const SCHEMA = {
  user: 'urn:ietf:params:scim:schemas:core:2.0:User',
  group: 'urn:ietf:params:scim:schemas:core:2.0:Group',
  list: 'urn:ietf:params:scim:api:messages:2.0:ListResponse',
  patch: 'urn:ietf:params:scim:api:messages:2.0:PatchOp',
  error: 'urn:ietf:params:scim:api:messages:2.0:Error',
};

class ScimError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly scimType?: string,
  ) {
    super(message);
  }
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type Json = Record<string, unknown>;

const str = (v: unknown, max = 300): string | undefined => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : undefined);

/** Entra ID sends booleans as "True"/"False" strings. */
function bool(v: unknown): boolean | undefined {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string' && /^(true|false)$/i.test(v)) return v.toLowerCase() === 'true';
  return undefined;
}

function emailFrom(body: Json): string {
  const emails = Array.isArray(body.emails) ? (body.emails as Json[]) : [];
  const primary = emails.find((e) => e.primary === true || bool(e.primary)) ?? emails[0];
  const candidates = [str(body.userName), str(primary?.value)];
  const email = candidates.find((c) => c && EMAIL.test(c))?.toLowerCase();
  if (!email || email.length > 254) throw new ScimError(400, 'userName (or a primary e-mail) must be an e-mail address', 'invalidValue');
  return email;
}

function nameFrom(body: Json): string | undefined {
  const name = (body.name ?? {}) as Json;
  return str(body.displayName, 100) ?? str(name.formatted, 100) ?? ([str(name.givenName), str(name.familyName)].filter(Boolean).join(' ') || undefined);
}

/** Supports the filters IdPs actually send: `attr eq "value"`. */
function parseFilter(filter: unknown, allowed: Record<string, string>): { column: string; value: string } | null {
  if (typeof filter !== 'string' || !filter.trim()) return null;
  const m = /^\s*([\w.]+)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$/i.exec(filter);
  const column = m ? allowed[m[1]!.toLowerCase()] : undefined;
  if (!m || !column) throw new ScimError(400, `Unsupported filter: ${filter.slice(0, 100)}`, 'invalidFilter');
  return { column, value: m[2]!.replace(/\\(.)/g, '$1') };
}

function paging(query: Json) {
  const startIndex = Math.max(1, Number(query.startIndex) || 1);
  const count = Math.min(200, Math.max(0, Number.isFinite(Number(query.count)) && query.count !== undefined ? Number(query.count) : 100));
  return { startIndex, count };
}

function list(resources: unknown[], total: number, startIndex: number) {
  return { schemas: [SCHEMA.list], totalResults: total, startIndex, itemsPerPage: resources.length, Resources: resources };
}

interface Ctx {
  orgId: string;
  tokenId: string;
  base: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    scim?: Ctx;
  }
}

interface MemberRow {
  id: string;
  email: string;
  role: string;
  status: string;
  external_id: string | null;
  display_name: string | null;
  user_name: string | null;
  revoked_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

const MEMBER_SELECT = `SELECT m.*, u.name AS user_name FROM org_members m LEFT JOIN users u ON u.id = m.user_id`;

function toUser(ctx: Ctx, r: MemberRow) {
  const name = r.display_name ?? r.user_name ?? r.email.split('@')[0]!;
  return {
    schemas: [SCHEMA.user],
    id: r.id,
    ...(r.external_id ? { externalId: r.external_id } : {}),
    userName: r.email,
    name: { formatted: name },
    displayName: name,
    emails: [{ value: r.email, type: 'work', primary: true }],
    active: !r.revoked_at,
    meta: {
      resourceType: 'User',
      created: r.created_at.toISOString(),
      lastModified: r.updated_at.toISOString(),
      location: `${ctx.base}/Users/${r.id}`,
    },
  };
}

async function toGroup(ctx: Ctx, client: Queryable, g: { id: string; name: string; external_id: string | null; created_at: Date }, withMembers = true) {
  const members = withMembers
    ? (
        await client.query<{ id: string; email: string }>(
          'SELECT m.id, m.email FROM group_members gm JOIN org_members m ON m.id = gm.member_id WHERE gm.group_id = $1 ORDER BY m.email',
          [g.id],
        )
      ).rows.map((m) => ({ value: m.id, display: m.email, $ref: `${ctx.base}/Users/${m.id}` }))
    : undefined;
  return {
    schemas: [SCHEMA.group],
    id: g.id,
    displayName: g.name,
    ...(g.external_id ? { externalId: g.external_id } : {}),
    ...(members ? { members } : {}),
    meta: { resourceType: 'Group', created: g.created_at.toISOString(), location: `${ctx.base}/Groups/${g.id}` },
  };
}

export async function scimRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;
  const base = `${config.PUBLIC_URL.replace(/\/$/, '')}/api/scim/v2`;

  app.addContentTypeParser('application/scim+json', { parseAs: 'string' }, app.getDefaultJsonParser('error', 'ignore'));

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof ScimError) {
      return reply.status(err.status).type('application/scim+json').send({
        schemas: [SCHEMA.error],
        status: String(err.status),
        detail: err.message,
        ...(err.scimType ? { scimType: err.scimType } : {}),
      });
    }
    const pgCode = (err as { code?: string }).code;
    const status = pgCode === '23505' ? 409 : pgCode === '23503' || pgCode === '22P02' ? 400 : ((err as { statusCode?: number }).statusCode ?? 500);
    if (status >= 500) req.log.error(err);
    return reply.status(status).type('application/scim+json').send({
      schemas: [SCHEMA.error],
      status: String(status),
      detail: status >= 500 ? 'Internal server error' : pgCode === '23505' ? 'Resource already exists' : (err as Error).message,
      ...(pgCode === '23505' ? { scimType: 'uniqueness' } : {}),
    });
  });

  app.addHook('onSend', async (_req, reply, payload) => {
    if (String(reply.getHeader('content-type') ?? '').startsWith('application/json')) reply.type('application/scim+json');
    return payload;
  });

  app.addHook('preHandler', async (req) => {
    const header = req.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice(7).trim() : '';
    if (!token) throw new ScimError(401, 'Bearer token required');
    // Owner role: the token itself tells us which tenant this is.
    const { rows } = await db.query<{ id: string; org_id: string; stale: boolean }>(
      `SELECT id, org_id, (last_used_at IS NULL OR last_used_at < now() - interval '1 minute') AS stale FROM scim_tokens WHERE token_hash = $1`,
      [sha256(token)],
    );
    const t = rows[0];
    if (!t) throw new ScimError(401, 'Invalid SCIM token');
    if (t.stale) await db.query('UPDATE scim_tokens SET last_used_at = now() WHERE id = $1', [t.id]);
    req.scim = { orgId: t.org_id, tokenId: t.id, base };
  });

  const ctxOf = (req: FastifyRequest) => req.scim!;
  const tx = <T>(req: FastifyRequest, fn: (client: pg.PoolClient) => Promise<T>) => withOrgTx(db, { orgId: ctxOf(req).orgId, userId: '' }, fn);
  const audit = (client: Queryable, req: FastifyRequest, action: AuditAction, targetType: string, targetId: string, metadata: Json = {}) =>
    recordAudit(client, req, { orgId: ctxOf(req).orgId, userId: null, action, targetType, targetId, metadata: { ...metadata, via: 'scim', tokenId: ctxOf(req).tokenId } });

  type PendingInvite = { memberId: string; email: string; token: string };
  async function flushInvites(orgId: string, pending: PendingInvite[]) {
    if (!pending.length) return;
    const org = (await db.query<{ name: string }>('SELECT name FROM organizations WHERE id = $1', [orgId])).rows[0];
    for (const i of pending) {
      const link = `${config.PUBLIC_URL.replace(/\/$/, '')}/accept-invite?org=${orgId}&member=${i.memberId}&token=${i.token}&email=${encodeURIComponent(i.email)}`;
      try {
        await app.mailer.send({ to: i.email, ...inviteEmail({ orgName: org?.name ?? 'your organization', inviterName: 'Your identity provider', link, expiresDays: config.INVITE_TTL_DAYS }) });
      } catch (err) {
        app.log.error({ err, email: i.email }, 'Failed to send SCIM invitation e-mail');
      }
    }
  }

  // ---- discovery -------------------------------------------------------------------------

  app.get('/ServiceProviderConfig', async () => ({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    documentationUri: `${config.PUBLIC_URL.replace(/\/$/, '')}/`,
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [{ type: 'oauthbearertoken', name: 'Bearer token', description: 'Organization SCIM token', primary: true }],
  }));

  app.get('/ResourceTypes', async () =>
    list(
      [
        { schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'User', name: 'User', endpoint: '/Users', schema: SCHEMA.user },
        { schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'Group', name: 'Group', endpoint: '/Groups', schema: SCHEMA.group },
      ],
      2,
      1,
    ),
  );

  app.get('/Schemas', async () =>
    list(
      [
        { id: SCHEMA.user, name: 'User', attributes: ['userName', 'name', 'displayName', 'emails', 'active', 'externalId'].map((name) => ({ name })) },
        { id: SCHEMA.group, name: 'Group', attributes: ['displayName', 'members', 'externalId'].map((name) => ({ name })) },
      ],
      2,
      1,
    ),
  );

  // ---- users -------------------------------------------------------------------------------

  async function loadMember(client: Queryable, orgId: string, id: string): Promise<MemberRow> {
    if (!UUID.test(id)) throw new ScimError(404, 'User not found');
    const { rows } = await client.query<MemberRow>(`${MEMBER_SELECT} WHERE m.org_id = $1 AND m.id = $2`, [orgId, id]);
    if (!rows[0]) throw new ScimError(404, 'User not found');
    return rows[0];
  }

  /** Deactivation revokes access; the last owner can never be locked out by the IdP. */
  async function setActive(client: Queryable, req: FastifyRequest, m: MemberRow, active: boolean) {
    if (active === !m.revoked_at) return;
    if (!active && m.role === 'owner' && !m.revoked_at && (await countOwners(client, ctxOf(req).orgId)) <= 1) {
      throw new ScimError(400, 'The last owner of the organization cannot be deactivated', 'mutability');
    }
    await client.query(`UPDATE org_members SET revoked_at = ${active ? 'NULL' : 'now()'}, updated_at = now() WHERE id = $1`, [m.id]);
    await audit(client, req, active ? 'scim.user_updated' : 'scim.user_deprovisioned', 'member', m.id, { email: m.email, active });
  }

  async function applyUserFields(
    client: Queryable,
    req: FastifyRequest,
    m: MemberRow,
    fields: { email?: string; name?: string; externalId?: string | null; active?: boolean },
  ): Promise<MemberRow> {
    const { orgId } = ctxOf(req);
    if (fields.email && fields.email !== m.email) {
      if (m.status !== 'invited') throw new ScimError(400, 'userName can only change before the user accepts the invitation', 'mutability');
      await client.query('UPDATE org_members SET email = $2, updated_at = now() WHERE id = $1', [m.id, fields.email]);
    }
    if (fields.name !== undefined || fields.externalId !== undefined) {
      await client.query(
        `UPDATE org_members SET display_name = coalesce($2, display_name),
           external_id = CASE WHEN $4 THEN $3 ELSE external_id END, updated_at = now() WHERE id = $1`,
        [m.id, fields.name ?? null, fields.externalId ?? null, fields.externalId !== undefined],
      );
    }
    if (fields.active !== undefined) await setActive(client, req, m, fields.active);
    if (fields.email || fields.name !== undefined || fields.externalId !== undefined) {
      await audit(client, req, 'scim.user_updated', 'member', m.id, { email: fields.email ?? m.email });
    }
    return loadMember(client, orgId, m.id);
  }

  app.get('/Users', async (req) => {
    const ctx = ctxOf(req);
    const q = req.query as Json;
    const filter = parseFilter(q.filter, { username: 'm.email', externalid: 'm.external_id', 'emails.value': 'm.email', 'emails': 'm.email' });
    const { startIndex, count } = paging(q);
    return tx(req, async (client) => {
      const where = filter ? `AND ${filter.column} = $2` : '';
      const value = filter ? [filter.column === 'm.email' ? filter.value.toLowerCase() : filter.value] : [];
      const total = await client.query<{ n: string }>(`SELECT count(*) AS n FROM org_members m WHERE m.org_id = $1 ${where}`, [ctx.orgId, ...value]);
      const { rows } = await client.query<MemberRow>(
        `${MEMBER_SELECT} WHERE m.org_id = $1 ${where} ORDER BY m.created_at, m.id OFFSET ${startIndex - 1} LIMIT ${count}`,
        [ctx.orgId, ...value],
      );
      return list(rows.map((r) => toUser(ctx, r)), Number(total.rows[0]!.n), startIndex);
    });
  });

  app.get('/Users/:id', async (req) => {
    const ctx = ctxOf(req);
    return tx(req, async (client) => toUser(ctx, await loadMember(client, ctx.orgId, (req.params as { id: string }).id)));
  });

  app.post('/Users', { config: { rateLimit: { max: 600, timeWindow: '1 minute' } } }, async (req, reply) => {
    const ctx = ctxOf(req);
    const body = (req.body ?? {}) as Json;
    const email = emailFrom(body);
    const active = bool(body.active) ?? true;
    const pending: PendingInvite[] = [];
    const user = await tx(req, async (client) => {
      const exists = await client.query('SELECT 1 FROM org_members WHERE org_id = $1 AND email = $2', [ctx.orgId, email]);
      if (exists.rowCount) throw new ScimError(409, `${email} is already a member`, 'uniqueness');
      const id = randomUUID();
      const token = newRefreshToken();
      await client.query(
        `INSERT INTO org_members (id, org_id, email, role, status, invite_token_hash, invite_expires_at, external_id, display_name, revoked_at)
         VALUES ($1, $2, $3, 'member', 'invited', $4, now() + make_interval(days => $5), $6, $7, ${active ? 'NULL' : 'now()'})`,
        [id, ctx.orgId, email, sha256(token), config.INVITE_TTL_DAYS, str(body.externalId, 200) ?? null, nameFrom(body) ?? null],
      );
      await audit(client, req, 'scim.user_provisioned', 'member', id, { email, active });
      if (active) pending.push({ memberId: id, email, token });
      return toUser(ctx, await loadMember(client, ctx.orgId, id));
    });
    await flushInvites(ctx.orgId, pending);
    return reply.status(201).header('location', user.meta.location).send(user);
  });

  app.put('/Users/:id', async (req) => {
    const ctx = ctxOf(req);
    const body = (req.body ?? {}) as Json;
    return tx(req, async (client) => {
      const m = await loadMember(client, ctx.orgId, (req.params as { id: string }).id);
      const updated = await applyUserFields(client, req, m, {
        email: emailFrom(body),
        name: nameFrom(body),
        externalId: str(body.externalId, 200) ?? null,
        active: bool(body.active) ?? true,
      });
      return toUser(ctx, updated);
    });
  });

  app.patch('/Users/:id', async (req) => {
    const ctx = ctxOf(req);
    const ops = patchOps(req.body);
    return tx(req, async (client) => {
      let m = await loadMember(client, ctx.orgId, (req.params as { id: string }).id);
      for (const op of ops) {
        if (op.op === 'remove') {
          if (op.path?.toLowerCase() === 'externalid') m = await applyUserFields(client, req, m, { externalId: null });
          continue; // other attributes are required and can't be removed
        }
        const values: Json = op.path ? { [op.path]: op.value } : ((op.value ?? {}) as Json);
        const fields: { email?: string; name?: string; externalId?: string | null; active?: boolean } = {};
        for (const [rawKey, v] of Object.entries(values)) {
          const key = rawKey.toLowerCase();
          if (key === 'active') fields.active = bool(v);
          else if (key === 'username' || key.startsWith('emails')) {
            const e = typeof v === 'string' ? v : Array.isArray(v) ? str((v[0] as Json)?.value) : undefined;
            if (e && EMAIL.test(e)) fields.email = e.toLowerCase();
          } else if (key === 'externalid') fields.externalId = str(v, 200) ?? null;
          else if (key === 'displayname' || key === 'name.formatted') fields.name = str(v, 100);
          else if (key === 'name' && v && typeof v === 'object') fields.name = nameFrom({ name: v });
          else if (key === 'name.givenname' || key === 'name.familyname') fields.name = fields.name ?? str(v, 100);
        }
        if (fields.active === undefined && 'active' in Object.fromEntries(Object.keys(values).map((k) => [k.toLowerCase(), 1]))) {
          throw new ScimError(400, 'active must be a boolean', 'invalidValue');
        }
        m = await applyUserFields(client, req, m, fields);
      }
      return toUser(ctx, m);
    });
  });

  app.delete('/Users/:id', async (req, reply) => {
    const ctx = ctxOf(req);
    await tx(req, async (client) => {
      const m = await loadMember(client, ctx.orgId, (req.params as { id: string }).id);
      if (m.role === 'owner' && !m.revoked_at && (await countOwners(client, ctx.orgId)) <= 1) {
        throw new ScimError(400, 'The last owner of the organization cannot be removed', 'mutability');
      }
      await client.query('DELETE FROM org_members WHERE id = $1', [m.id]);
      await audit(client, req, 'scim.user_deleted', 'member', m.id, { email: m.email });
    });
    return reply.status(204).send();
  });

  // ---- groups ------------------------------------------------------------------------------

  interface GroupRow {
    id: string;
    name: string;
    external_id: string | null;
    created_at: Date;
  }

  async function loadGroup(client: Queryable, orgId: string, id: string): Promise<GroupRow> {
    if (!UUID.test(id)) throw new ScimError(404, 'Group not found');
    const { rows } = await client.query<GroupRow>('SELECT id, name, external_id, created_at FROM groups WHERE org_id = $1 AND id = $2', [orgId, id]);
    if (!rows[0]) throw new ScimError(404, 'Group not found');
    return rows[0];
  }

  function memberIds(value: unknown): string[] {
    const arr = Array.isArray(value) ? value : value ? [value] : [];
    const ids = arr.map((v) => (typeof v === 'string' ? v : str((v as Json)?.value))).filter((v): v is string => !!v);
    if (ids.some((id) => !UUID.test(id))) throw new ScimError(400, 'Unknown member id', 'invalidValue');
    return ids;
  }

  async function addMembers(client: Queryable, orgId: string, groupId: string, ids: string[]) {
    if (!ids.length) return;
    await client.query(
      'INSERT INTO group_members (group_id, member_id, org_id) SELECT $1, unnest($2::uuid[]), $3 ON CONFLICT DO NOTHING',
      [groupId, [...new Set(ids)], orgId],
    );
  }

  app.get('/Groups', async (req) => {
    const ctx = ctxOf(req);
    const q = req.query as Json;
    const filter = parseFilter(q.filter, { displayname: 'g.name', externalid: 'g.external_id' });
    const { startIndex, count } = paging(q);
    const excludeMembers = typeof q.excludedAttributes === 'string' && q.excludedAttributes.toLowerCase().includes('members');
    return tx(req, async (client) => {
      const where = filter ? `AND ${filter.column} = $2` : '';
      const value = filter ? [filter.value] : [];
      const total = await client.query<{ n: string }>(`SELECT count(*) AS n FROM groups g WHERE g.org_id = $1 ${where}`, [ctx.orgId, ...value]);
      const { rows } = await client.query<GroupRow>(
        `SELECT g.id, g.name, g.external_id, g.created_at FROM groups g WHERE g.org_id = $1 ${where}
          ORDER BY g.created_at, g.id OFFSET ${startIndex - 1} LIMIT ${count}`,
        [ctx.orgId, ...value],
      );
      const resources = [];
      for (const g of rows) resources.push(await toGroup(ctx, client, g, !excludeMembers));
      return list(resources, Number(total.rows[0]!.n), startIndex);
    });
  });

  app.get('/Groups/:id', async (req) => {
    const ctx = ctxOf(req);
    return tx(req, async (client) => toGroup(ctx, client, await loadGroup(client, ctx.orgId, (req.params as { id: string }).id)));
  });

  app.post('/Groups', async (req, reply) => {
    const ctx = ctxOf(req);
    const body = (req.body ?? {}) as Json;
    const name = str(body.displayName, 100);
    if (!name) throw new ScimError(400, 'displayName is required', 'invalidValue');
    const group = await tx(req, async (client) => {
      const id = randomUUID();
      // IdP groups are always marked as externally managed (SSO group sync matches on this too).
      await client.query('INSERT INTO groups (id, org_id, name, external_id) VALUES ($1, $2, $3, $4)', [id, ctx.orgId, name, str(body.externalId, 200) ?? name]);
      await addMembers(client, ctx.orgId, id, memberIds(body.members));
      await audit(client, req, 'scim.group_created', 'group', id, { name });
      return toGroup(ctx, client, await loadGroup(client, ctx.orgId, id));
    });
    return reply.status(201).header('location', group.meta.location).send(group);
  });

  app.put('/Groups/:id', async (req) => {
    const ctx = ctxOf(req);
    const body = (req.body ?? {}) as Json;
    return tx(req, async (client) => {
      const g = await loadGroup(client, ctx.orgId, (req.params as { id: string }).id);
      const name = str(body.displayName, 100) ?? g.name;
      await client.query('UPDATE groups SET name = $2, external_id = coalesce($3, external_id) WHERE id = $1', [g.id, name, str(body.externalId, 200) ?? null]);
      await client.query('DELETE FROM group_members WHERE group_id = $1', [g.id]);
      await addMembers(client, ctx.orgId, g.id, memberIds(body.members));
      await audit(client, req, 'scim.group_updated', 'group', g.id, { name });
      return toGroup(ctx, client, await loadGroup(client, ctx.orgId, g.id));
    });
  });

  app.patch('/Groups/:id', async (req, reply) => {
    const ctx = ctxOf(req);
    const ops = patchOps(req.body);
    await tx(req, async (client) => {
      const g = await loadGroup(client, ctx.orgId, (req.params as { id: string }).id);
      for (const op of ops) {
        const path = op.path?.trim();
        const filtered = path ? /^members\[value eq "([^"]+)"\]$/i.exec(path) : null;
        if (op.op === 'remove' && filtered) {
          await client.query('DELETE FROM group_members WHERE group_id = $1 AND member_id::text = $2', [g.id, filtered[1]]);
        } else if (path?.toLowerCase() === 'members') {
          const ids = memberIds(op.value);
          if (op.op === 'replace') await client.query('DELETE FROM group_members WHERE group_id = $1', [g.id]);
          if (op.op === 'remove') {
            if (ids.length) await client.query('DELETE FROM group_members WHERE group_id = $1 AND member_id = ANY($2::uuid[])', [g.id, ids]);
            else await client.query('DELETE FROM group_members WHERE group_id = $1', [g.id]);
          } else await addMembers(client, ctx.orgId, g.id, ids);
        } else {
          const values = (path ? { [path]: op.value } : (op.value ?? {})) as Json;
          for (const [rawKey, v] of Object.entries(values)) {
            const key = rawKey.toLowerCase();
            if (key === 'displayname' && str(v, 100)) await client.query('UPDATE groups SET name = $2 WHERE id = $1', [g.id, str(v, 100)]);
            else if (key === 'externalid' && str(v, 200)) await client.query('UPDATE groups SET external_id = $2 WHERE id = $1', [g.id, str(v, 200)]);
            else if (key === 'members') {
              if (op.op === 'replace') await client.query('DELETE FROM group_members WHERE group_id = $1', [g.id]);
              await addMembers(client, ctx.orgId, g.id, memberIds(v));
            }
          }
        }
      }
      await audit(client, req, 'scim.group_updated', 'group', g.id, { operations: ops.length });
    });
    return reply.status(204).send();
  });

  app.delete('/Groups/:id', async (req, reply) => {
    const ctx = ctxOf(req);
    await tx(req, async (client) => {
      const g = await loadGroup(client, ctx.orgId, (req.params as { id: string }).id);
      await client.query('DELETE FROM groups WHERE id = $1', [g.id]);
      await audit(client, req, 'scim.group_deleted', 'group', g.id, { name: g.name });
    });
    return reply.status(204).send();
  });
}

function patchOps(body: unknown): { op: 'add' | 'remove' | 'replace'; path?: string; value?: unknown }[] {
  const ops = (body as Json | null)?.Operations;
  if (!Array.isArray(ops) || ops.length === 0 || ops.length > 100) throw new ScimError(400, 'PatchOp needs 1–100 Operations', 'invalidSyntax');
  return ops.map((o: Json) => {
    const op = String(o.op ?? '').toLowerCase();
    if (op !== 'add' && op !== 'remove' && op !== 'replace') throw new ScimError(400, `Unsupported op: ${String(o.op)}`, 'invalidSyntax');
    return { op, path: typeof o.path === 'string' ? o.path : undefined, value: o.value };
  });
}

