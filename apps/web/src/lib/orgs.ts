import {
  decryptCollectionName,
  encryptCollectionName,
  generateOrgKey,
  sealOrgKey,
  toB64,
  uuid,
  wipe,
} from '@enclavier/crypto';
import type {
  AcceptInviteRequest,
  InvitePreview,
  InviteRequest,
  OrgCollection,
  OrgEvent,
  OrgGroup,
  OrgMember,
  OrgRole,
  Permission,
} from '@enclavier/shared';
import { api } from './api';
import { requireAccountKeys, requireOrgKey, useSession } from './session';

export type Grant = { id: string; permission: Permission };

// ---- organizations ----------------------------------------------------------

/** Creates the org key in the browser and seals it to our own public key. */
export async function createOrganization(name: string): Promise<string> {
  const keys = requireAccountKeys();
  const orgId = uuid();
  const collectionId = uuid();
  const orgKey = generateOrgKey();
  try {
    await api('POST', '/api/orgs', {
      id: orgId,
      name,
      protectedOrgKey: sealOrgKey(toB64(keys.publicKey), orgKey, orgId),
      defaultCollection: { id: collectionId, name: encryptCollectionName(orgKey, collectionId, 'Default collection') },
    });
  } finally {
    wipe(orgKey);
  }
  await useSession.getState().sync();
  return orgId;
}

export const renameOrganization = (orgId: string, name: string) => api('PATCH', `/api/orgs/${orgId}`, { name });

export async function deleteOrganization(orgId: string, password: string): Promise<void> {
  const authHash = await useSession.getState().verifyPassword(password);
  await api('POST', `/api/orgs/${orgId}/delete`, { authHash });
  await useSession.getState().sync();
}

export async function leaveOrganization(orgId: string): Promise<void> {
  await api('POST', `/api/orgs/${orgId}/leave`);
  await useSession.getState().sync();
}

// ---- invitations --------------------------------------------------------------

const PENDING_INVITE = 'enclavier.pendingInvite';

export interface PendingInvite extends AcceptInviteRequest {
  email: string;
}

export function readInviteFromUrl(search: string): PendingInvite | null {
  const p = new URLSearchParams(search);
  const orgId = p.get('org');
  const memberId = p.get('member');
  const token = p.get('token');
  if (!orgId || !memberId || !token) return null;
  return { orgId, memberId, token, email: (p.get('email') ?? '').toLowerCase() };
}

export function savePendingInvite(invite: PendingInvite | null): void {
  if (invite) sessionStorage.setItem(PENDING_INVITE, JSON.stringify(invite));
  else sessionStorage.removeItem(PENDING_INVITE);
}

export function loadPendingInvite(): PendingInvite | null {
  try {
    return JSON.parse(sessionStorage.getItem(PENDING_INVITE) ?? 'null') as PendingInvite | null;
  } catch {
    return null;
  }
}

export const previewInvite = (i: AcceptInviteRequest) =>
  api<InvitePreview>('GET', `/api/invites/${i.orgId}/${i.memberId}?token=${encodeURIComponent(i.token)}`, undefined, { auth: false });

export async function acceptInvite(i: AcceptInviteRequest): Promise<void> {
  await api('POST', '/api/invites/accept', { orgId: i.orgId, memberId: i.memberId, token: i.token });
  savePendingInvite(null);
  await useSession.getState().sync();
}

// ---- members ------------------------------------------------------------------

export const listMembers = (orgId: string) => api<OrgMember[]>('GET', `/api/orgs/${orgId}/members`);

export const inviteMembers = (orgId: string, body: InviteRequest) =>
  api<{ invited: string[]; skipped: string[] }>('POST', `/api/orgs/${orgId}/members/invite`, body);

export const reinviteMember = (orgId: string, memberId: string) => api('POST', `/api/orgs/${orgId}/members/${memberId}/reinvite`);

/** Seals our copy of the org key to the member's public key. The server never sees the key. */
export async function confirmMember(orgId: string, member: OrgMember): Promise<void> {
  if (!member.publicKey) throw new Error('This member has not accepted the invitation yet');
  await api('POST', `/api/orgs/${orgId}/members/${member.id}/confirm`, {
    protectedOrgKey: sealOrgKey(member.publicKey, requireOrgKey(orgId), orgId),
  });
}

export const updateMember = (orgId: string, memberId: string, body: { role: OrgRole; collections: Grant[]; groups: string[] }) =>
  api('PUT', `/api/orgs/${orgId}/members/${memberId}`, body);

export const setMemberRevoked = (orgId: string, memberId: string, revoked: boolean) =>
  api('POST', `/api/orgs/${orgId}/members/${memberId}/${revoked ? 'revoke' : 'restore'}`);

export const removeMember = (orgId: string, memberId: string) => api('DELETE', `/api/orgs/${orgId}/members/${memberId}`);

// ---- groups -------------------------------------------------------------------

export const listGroups = (orgId: string) => api<OrgGroup[]>('GET', `/api/orgs/${orgId}/groups`);

export function saveGroup(orgId: string, group: { id?: string; name: string; memberIds: string[]; collections: Grant[]; externalId?: string | null }) {
  const body = { name: group.name, memberIds: group.memberIds, collections: group.collections, externalId: group.externalId || null };
  return group.id ? api('PUT', `/api/orgs/${orgId}/groups/${group.id}`, body) : api('POST', `/api/orgs/${orgId}/groups`, body);
}

export const deleteGroup = (orgId: string, groupId: string) => api('DELETE', `/api/orgs/${orgId}/groups/${groupId}`);

// ---- collections ----------------------------------------------------------------

export interface AdminCollection extends Omit<OrgCollection, 'name'> {
  name: string;
}

export async function listCollections(orgId: string): Promise<AdminCollection[]> {
  const orgKey = requireOrgKey(orgId);
  const rows = await api<OrgCollection[]>('GET', `/api/orgs/${orgId}/collections`);
  return rows.map((c) => {
    try {
      return { ...c, name: decryptCollectionName(orgKey, c.id, c.name) };
    } catch {
      return { ...c, name: '⚠ Undecryptable collection' };
    }
  });
}

export async function saveCollection(
  orgId: string,
  c: { id?: string; name: string; members: { memberId: string; permission: Permission }[]; groups: { groupId: string; permission: Permission }[] },
): Promise<void> {
  const id = c.id ?? uuid();
  const body = { name: encryptCollectionName(requireOrgKey(orgId), id, c.name), members: c.members, groups: c.groups };
  if (c.id) await api('PUT', `/api/orgs/${orgId}/collections/${id}`, body);
  else await api('POST', `/api/orgs/${orgId}/collections`, { id, ...body });
  await useSession.getState().sync();
}

export async function deleteCollection(orgId: string, collectionId: string): Promise<void> {
  await api('DELETE', `/api/orgs/${orgId}/collections/${collectionId}`);
  await useSession.getState().sync();
}

// ---- events ---------------------------------------------------------------------

export const listEvents = (orgId: string, before?: number) =>
  api<OrgEvent[]>('GET', `/api/orgs/${orgId}/events?limit=100${before ? `&before=${before}` : ''}`);

export const PERMISSION_LABELS: Record<Permission, { label: string; hint: string }> = {
  use: { label: 'Use (masked)', hint: 'Sees item names and usernames; passwords and hidden fields stay masked' },
  view: { label: 'View', hint: 'Can view and copy secrets' },
  edit: { label: 'Edit', hint: 'Can add, edit and trash items' },
  manage: { label: 'Manage', hint: 'Can also manage access and permanently delete items' },
};

export const ROLE_LABELS: Record<OrgRole, { label: string; hint: string }> = {
  owner: { label: 'Owner', hint: 'Full control, including owners, billing and deleting the organization' },
  admin: { label: 'Admin', hint: 'Manages members, groups and all collections' },
  member: { label: 'Member', hint: 'Accesses only the collections granted to them or their groups' },
};
