import { PERMISSION_RANK, type MemberStatus, type OrgRole, type Permission, type PolicyType } from '@enclavier/shared';
import type { Queryable } from '../db';
import { forbidden, notFound } from '../errors';

export interface Membership {
  id: string;
  orgId: string;
  userId: string;
  email: string;
  role: OrgRole;
  status: MemberStatus;
  revoked: boolean;
}

const RANK_TO_PERMISSION: Permission[] = ['use', 'use', 'view', 'edit', 'manage'];

/**
 * Loads the caller's membership. Non-members get 404 (not 403) so the
 * existence of other organizations is not disclosed.
 */
export async function loadMembership(client: Queryable, orgId: string, userId: string): Promise<Membership> {
  const { rows } = await client.query(
    'SELECT id, org_id, user_id, email, role, status, revoked_at FROM org_members WHERE org_id = $1 AND user_id = $2',
    [orgId, userId],
  );
  const r = rows[0];
  if (!r) throw notFound('Organization not found');
  return { id: r.id, orgId: r.org_id, userId: r.user_id, email: r.email, role: r.role, status: r.status, revoked: !!r.revoked_at };
}

export interface PolicyRow {
  type: PolicyType;
  enabled: boolean;
  data: Record<string, unknown>;
}

export async function loadPolicies(client: Queryable, orgId: string): Promise<Map<PolicyRow['type'], PolicyRow>> {
  const { rows } = await client.query<PolicyRow>('SELECT type, enabled, data FROM org_policies WHERE org_id = $1', [orgId]);
  return new Map(rows.map((r) => [r.type, r]));
}

export async function userHasTwoFactor(client: Queryable, userId: string): Promise<boolean> {
  const { rows } = await client.query<{ ok: boolean }>(
    `SELECT (u.totp_enabled_at IS NOT NULL OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)) AS ok
       FROM users u WHERE u.id = $1`,
    [userId],
  );
  return !!rows[0]?.ok;
}

/** Returns why a policy blocks this user from the org's data, or null. */
export async function policyBlock(client: Queryable, orgId: string, userId: string): Promise<string | null> {
  const policies = await loadPolicies(client, orgId);
  if (policies.get('require_2fa')?.enabled && !(await userHasTwoFactor(client, userId))) {
    return 'require_2fa';
  }
  return null;
}

/** A member who can currently use the organization (confirmed, not revoked, compliant with policies). */
export async function requireActiveMember(client: Queryable, orgId: string, userId: string): Promise<Membership> {
  const m = await loadMembership(client, orgId, userId);
  if (m.revoked) throw forbidden('Your access to this organization has been revoked');
  if (m.status !== 'confirmed') throw forbidden('Your membership is awaiting confirmation by an administrator');
  if ((await policyBlock(client, orgId, userId)) === 'require_2fa') {
    throw forbidden('This organization requires two-step login. Turn it on in Settings → Security to regain access.');
  }
  return m;
}

export const isAdmin = (m: Membership) => m.role === 'owner' || m.role === 'admin';

export async function requireAdmin(client: Queryable, orgId: string, userId: string): Promise<Membership> {
  const m = await requireActiveMember(client, orgId, userId);
  if (!isAdmin(m)) throw forbidden('Administrator role required');
  return m;
}

export async function requireOwner(client: Queryable, orgId: string, userId: string): Promise<Membership> {
  const m = await requireActiveMember(client, orgId, userId);
  if (m.role !== 'owner') throw forbidden('Owner role required');
  return m;
}

/**
 * Effective permission per collection for a member: the strongest of direct
 * grants and grants through any of the member's groups. Owners and admins
 * implicitly manage every collection.
 */
export async function collectionPermissions(client: Queryable, m: Membership): Promise<Map<string, Permission>> {
  const result = new Map<string, Permission>();
  if (isAdmin(m)) {
    const { rows } = await client.query<{ id: string }>('SELECT id FROM collections WHERE org_id = $1', [m.orgId]);
    for (const r of rows) result.set(r.id, 'manage');
    return result;
  }
  const { rows } = await client.query<{ collection_id: string; rank: number }>(
    `SELECT ca.collection_id,
            max(CASE ca.permission WHEN 'use' THEN 1 WHEN 'view' THEN 2 WHEN 'edit' THEN 3 ELSE 4 END) AS rank
       FROM collection_access ca
       LEFT JOIN group_members gm ON gm.group_id = ca.group_id
      WHERE ca.org_id = $1 AND (ca.member_id = $2 OR gm.member_id = $2)
      GROUP BY ca.collection_id`,
    [m.orgId, m.id],
  );
  for (const r of rows) result.set(r.collection_id, RANK_TO_PERMISSION[Number(r.rank)]!);
  return result;
}

export async function requireCollection(client: Queryable, m: Membership, collectionId: string, min: Permission): Promise<Permission> {
  const perms = await collectionPermissions(client, m);
  const p = perms.get(collectionId);
  if (!p) throw notFound('Collection not found');
  if (PERMISSION_RANK[p] < PERMISSION_RANK[min]) throw forbidden(`This action needs "${min}" permission on the collection`);
  return p;
}

export async function countOwners(client: Queryable, orgId: string): Promise<number> {
  const { rows } = await client.query<{ n: string }>(
    `SELECT count(*) AS n FROM org_members WHERE org_id = $1 AND role = 'owner' AND status = 'confirmed' AND revoked_at IS NULL`,
    [orgId],
  );
  return Number(rows[0]!.n);
}
