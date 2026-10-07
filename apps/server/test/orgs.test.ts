import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  decryptCollectionName,
  decryptItem,
  encryptCollectionName,
  encryptItem,
  generateOrgKey,
  openOrgKey,
  rewrapItemKey,
  sealOrgKey,
  toB64,
  uuid,
} from '@enclavier/crypto';
import type { OrgMember, SyncResponse } from '@enclavier/shared';
import { verifyAuditChain } from '../src/audit';
import { withOrgTx, type Db } from '../src/db';
import type { MailMessage } from '../src/mail';
import { DATABASE_URL, registerUser, resetDb, setupApp, type TestUser } from './helpers';

function inviteLink(mail: MailMessage) {
  const url = new URL(mail.text.match(/https:\/\/\S+/)![0]);
  return { orgId: url.searchParams.get('org')!, memberId: url.searchParams.get('member')!, token: url.searchParams.get('token')! };
}

describe.skipIf(!DATABASE_URL)('Organizations (integration)', () => {
  let app: FastifyInstance;
  let db: Db;
  let outbox: MailMessage[];
  let alice: TestUser; // owner
  let bob: TestUser; // invited member
  let mallory: TestUser; // another tenant

  const orgId = uuid();
  const defaultCollection = uuid();
  const secretsCollection = uuid();
  const orgKey = generateOrgKey();
  let bobMemberId = '';
  let groupId = '';

  const sync = async (u: TestUser) => (await app.inject({ method: 'GET', url: '/api/sync', headers: u.auth })).json() as SyncResponse;

  beforeAll(async () => {
    db = await resetDb();
    ({ app, outbox } = await setupApp(db));
    alice = await registerUser(app, 'alice@acme.test');
    bob = await registerUser(app, 'bob@acme.test');
    mallory = await registerUser(app, 'mallory@evil.test');
  });

  afterAll(async () => {
    await app?.close();
    await db?.end();
  });

  it('creates an organization with a key only the owner can open', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/orgs',
      headers: alice.auth,
      payload: {
        id: orgId,
        name: 'Acme Corp',
        protectedOrgKey: sealOrgKey(toB64(alice.keys.publicKey), orgKey, orgId),
        defaultCollection: { id: defaultCollection, name: encryptCollectionName(orgKey, defaultCollection, 'Default') },
      },
    });
    expect(res.statusCode).toBe(201);

    const s = await sync(alice);
    expect(s.organizations).toHaveLength(1);
    expect(s.organizations[0]).toMatchObject({ role: 'owner', status: 'confirmed' });
    const opened = openOrgKey(alice.keys.privateKey, s.organizations[0]!.protectedOrgKey!, orgId);
    expect(opened).toEqual(orgKey);
    expect(decryptCollectionName(opened, defaultCollection, s.collections[0]!.name)).toBe('Default');
    // The org key is bound to this org id: it can't be replayed onto another org.
    expect(() => openOrgKey(alice.keys.privateKey, s.organizations[0]!.protectedOrgKey!, uuid())).toThrow();
  });

  it('invites by e-mail and only the invited account can accept', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/orgs/${orgId}/members/invite`,
      headers: alice.auth,
      payload: { emails: ['BOB@acme.test', 'dave@acme.test'], role: 'member', collections: [{ id: defaultCollection, permission: 'view' }] },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().invited).toEqual(['bob@acme.test', 'dave@acme.test']);
    const invites = outbox.filter((m) => m.subject.includes('invited you'));
    expect(invites.map((m) => m.to)).toEqual(['bob@acme.test', 'dave@acme.test']);
    expect(invites[0]!.subject).toContain('Acme Corp');

    const link = inviteLink(invites[0]!);
    bobMemberId = link.memberId;
    const preview = await app.inject({ method: 'GET', url: `/api/invites/${link.orgId}/${link.memberId}?token=${link.token}` });
    expect(preview.json()).toMatchObject({ orgName: 'Acme Corp', email: 'bob@acme.test', inviterName: 'alice' });
    const badPreview = await app.inject({ method: 'GET', url: `/api/invites/${link.orgId}/${link.memberId}?token=${'x'.repeat(43)}` });
    expect(badPreview.statusCode).toBe(404);

    const wrongUser = await app.inject({ method: 'POST', url: '/api/invites/accept', headers: mallory.auth, payload: link });
    expect(wrongUser.statusCode).toBe(403);
    const accepted = await app.inject({ method: 'POST', url: '/api/invites/accept', headers: bob.auth, payload: link });
    expect(accepted.statusCode).toBe(200);
    const replay = await app.inject({ method: 'POST', url: '/api/invites/accept', headers: bob.auth, payload: link });
    expect(replay.statusCode).toBe(404);

    // Accepted but not yet confirmed: Bob sees the org, but no key and no data.
    const s = await sync(bob);
    expect(s.organizations[0]).toMatchObject({ status: 'accepted', protectedOrgKey: null });
    expect(s.collections).toHaveLength(0);
  });

  it('admin confirms the member by sealing the org key to their public key', async () => {
    const members = (await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/members`, headers: alice.auth })).json() as OrgMember[];
    const bobRow = members.find((m) => m.id === bobMemberId)!;
    expect(bobRow.status).toBe('accepted');
    expect(bobRow.publicKey).toBe(toB64(bob.keys.publicKey));
    expect(members.find((m) => m.email === 'dave@acme.test')!.publicKey).toBeNull();

    const notAdmin = await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/members`, headers: bob.auth });
    expect(notAdmin.statusCode).toBe(403);

    const res = await app.inject({
      method: 'POST',
      url: `/api/orgs/${orgId}/members/${bobMemberId}/confirm`,
      headers: alice.auth,
      payload: { protectedOrgKey: sealOrgKey(bobRow.publicKey!, orgKey, orgId) },
    });
    expect(res.statusCode).toBe(204);
    const s = await sync(bob);
    expect(openOrgKey(bob.keys.privateKey, s.organizations[0]!.protectedOrgKey!, orgId)).toEqual(orgKey);
    expect(s.collections).toEqual([expect.objectContaining({ id: defaultCollection, permission: 'view' })]);
  });

  it('enforces collection permissions for members', async () => {
    const itemId = uuid();
    const created = await app.inject({
      method: 'POST',
      url: `/api/orgs/${orgId}/items`,
      headers: alice.auth,
      payload: { ...encryptItem(orgKey, itemId, null, { type: 'login', name: 'AWS root' }), collectionId: defaultCollection },
    });
    expect(created.statusCode).toBe(201);

    const s = await sync(bob);
    const shared = s.items.find((i) => i.id === itemId)!;
    expect(decryptItem<{ name: string }>(orgKey, shared).name).toBe('AWS root');

    // "view" cannot write.
    const edit = await app.inject({
      method: 'PUT',
      url: `/api/orgs/${orgId}/items/${itemId}`,
      headers: bob.auth,
      payload: { collectionId: defaultCollection, data: shared.data, revision: shared.revision },
    });
    expect(edit.statusCode).toBe(403);
    const create = await app.inject({
      method: 'POST',
      url: `/api/orgs/${orgId}/items`,
      headers: bob.auth,
      payload: { ...encryptItem(orgKey, uuid(), null, { type: 'note', name: 'x' }), collectionId: defaultCollection },
    });
    expect(create.statusCode).toBe(403);
  });

  it('grants access through groups', async () => {
    await app.inject({
      method: 'POST',
      url: `/api/orgs/${orgId}/collections`,
      headers: alice.auth,
      payload: { id: secretsCollection, name: encryptCollectionName(orgKey, secretsCollection, 'Prod secrets'), members: [], groups: [] },
    });
    expect((await sync(bob)).collections.map((c) => c.id)).not.toContain(secretsCollection);

    const res = await app.inject({
      method: 'POST',
      url: `/api/orgs/${orgId}/groups`,
      headers: alice.auth,
      payload: { name: 'Engineering', memberIds: [bobMemberId], collections: [{ id: secretsCollection, permission: 'edit' }] },
    });
    expect(res.statusCode).toBe(201);
    groupId = res.json().id;

    const s = await sync(bob);
    expect(s.collections.find((c) => c.id === secretsCollection)?.permission).toBe('edit');
    const create = await app.inject({
      method: 'POST',
      url: `/api/orgs/${orgId}/items`,
      headers: bob.auth,
      payload: { ...encryptItem(orgKey, uuid(), null, { type: 'login', name: 'DB password' }), collectionId: secretsCollection },
    });
    expect(create.statusCode).toBe(201);
  });

  it('shares a personal item into a collection by re-wrapping only its key', async () => {
    const itemId = uuid();
    const personal = encryptItem(alice.keys.userKey, itemId, null, { type: 'login', name: 'Stripe' });
    const made = await app.inject({ method: 'POST', url: '/api/items', headers: alice.auth, payload: personal });
    expect(made.statusCode).toBe(201);

    const res = await app.inject({
      method: 'POST',
      url: `/api/items/${itemId}/share`,
      headers: alice.auth,
      payload: { orgId, collectionId: defaultCollection, key: rewrapItemKey(alice.keys.userKey, orgKey, itemId, personal.key), revision: 1 },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().data).toBe(personal.data); // data ciphertext untouched

    const s = await sync(bob);
    expect(decryptItem<{ name: string }>(orgKey, s.items.find((i) => i.id === itemId)!).name).toBe('Stripe');
  });

  it('isolates tenants, including at the database layer (RLS)', async () => {
    const malloryOrg = uuid();
    const malloryKey = generateOrgKey();
    const mcol = uuid();
    await app.inject({
      method: 'POST',
      url: '/api/orgs',
      headers: mallory.auth,
      payload: {
        id: malloryOrg,
        name: 'Evil Inc',
        protectedOrgKey: sealOrgKey(toB64(mallory.keys.publicKey), malloryKey, malloryOrg),
        defaultCollection: { id: mcol, name: encryptCollectionName(malloryKey, mcol, 'Default') },
      },
    });

    for (const url of [`/api/orgs/${orgId}/members`, `/api/orgs/${orgId}/collections`, `/api/orgs/${orgId}/events`]) {
      expect((await app.inject({ method: 'GET', url, headers: mallory.auth })).statusCode).toBe(404);
    }
    // Referencing another tenant's collection from Mallory's org is rejected by the composite FKs.
    const crossRef = await app.inject({
      method: 'POST',
      url: `/api/orgs/${malloryOrg}/groups`,
      headers: mallory.auth,
      payload: { name: 'steal', memberIds: [], collections: [{ id: defaultCollection, permission: 'manage' }] },
    });
    expect(crossRef.statusCode).toBe(400);

    // Even an unfiltered query inside Mallory's tenant scope can't see Acme rows.
    const leaked = await withOrgTx(db, { orgId: malloryOrg, userId: mallory.id }, async (c) => ({
      items: (await c.query('SELECT org_id FROM items')).rows,
      members: (await c.query('SELECT org_id FROM org_members')).rows,
      orgs: (await c.query('SELECT id FROM organizations')).rows,
      collections: (await c.query('SELECT org_id FROM collections')).rows,
    }));
    expect(leaked.orgs).toEqual([{ id: malloryOrg }]);
    for (const rows of [leaked.items, leaked.members, leaked.collections]) {
      expect(rows.every((r: { org_id: string | null }) => r.org_id !== orgId)).toBe(true);
    }
  });

  it('revoking a member cuts off access immediately', async () => {
    expect((await app.inject({ method: 'POST', url: `/api/orgs/${orgId}/members/${bobMemberId}/revoke`, headers: alice.auth })).statusCode).toBe(204);
    const s = await sync(bob);
    expect(s.organizations).toHaveLength(0);
    expect(s.items.filter((i) => i.orgId)).toHaveLength(0);
    expect((await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/collections`, headers: bob.auth })).statusCode).toBe(403);

    await app.inject({ method: 'POST', url: `/api/orgs/${orgId}/members/${bobMemberId}/restore`, headers: alice.auth });
    expect((await sync(bob)).organizations).toHaveLength(1);
  });

  it('protects the last owner', async () => {
    const leave = await app.inject({ method: 'POST', url: `/api/orgs/${orgId}/leave`, headers: alice.auth });
    expect(leave.statusCode).toBe(400);
    const members = (await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/members`, headers: alice.auth })).json() as OrgMember[];
    const aliceRow = members.find((m) => m.email === alice.email)!;
    const demote = await app.inject({
      method: 'PUT',
      url: `/api/orgs/${orgId}/members/${aliceRow.id}`,
      headers: alice.auth,
      payload: { role: 'admin', collections: [], groups: [] },
    });
    expect(demote.statusCode).toBe(400);

    // Admins cannot promote to owner.
    await app.inject({
      method: 'PUT',
      url: `/api/orgs/${orgId}/members/${bobMemberId}`,
      headers: alice.auth,
      payload: { role: 'admin', collections: [], groups: [groupId] },
    });
    const escalate = await app.inject({
      method: 'PUT',
      url: `/api/orgs/${orgId}/members/${bobMemberId}`,
      headers: bob.auth,
      payload: { role: 'owner', collections: [], groups: [] },
    });
    expect(escalate.statusCode).toBe(403);
  });

  it('records an org event log and keeps the audit chain intact', async () => {
    const events = (await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/events`, headers: alice.auth })).json();
    const actions = events.map((e: { action: string }) => e.action);
    for (const a of ['org.created', 'member.invited', 'member.accepted', 'member.confirmed', 'group.created', 'item.shared', 'member.revoked']) {
      expect(actions).toContain(a);
    }
    expect((await verifyAuditChain(db)).ok).toBe(true);
  });

  it('lets invited users register when public sign-up is disabled', async () => {
    const closed = await setupApp(db, { SIGNUPS_ENABLED: 'false' });
    try {
      await expect(registerUser(closed.app, 'stranger@acme.test')).rejects.toThrow(/403/);
      const dave = inviteLink(outbox.find((m) => m.to === 'dave@acme.test' && m.subject.includes('invited you'))!);
      await expect(registerUser(closed.app, 'eve@acme.test', undefined, { invite: dave })).rejects.toThrow(/403/);
      const u = await registerUser(closed.app, 'dave@acme.test', undefined, { invite: dave });
      expect(u.id).toBeTruthy();
    } finally {
      await closed.app.close();
    }
  });
});
