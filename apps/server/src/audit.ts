import { createHash } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import type { Db, Queryable } from './db';

export type AuditAction =
  | 'user.register'
  | 'user.login'
  | 'user.login_failed'
  | 'user.logout'
  | 'user.password_changed'
  | 'user.deleted'
  | 'session.refresh_reuse_detected'
  | 'session.revoked'
  | 'folder.created'
  | 'folder.updated'
  | 'folder.deleted'
  | 'item.created'
  | 'item.updated'
  | 'item.trashed'
  | 'item.restored'
  | 'item.deleted'
  | 'vault.exported'
  | 'item.shared'
  | 'org.created'
  | 'org.updated'
  | 'org.deleted'
  | 'member.invited'
  | 'member.reinvited'
  | 'member.accepted'
  | 'member.confirmed'
  | 'member.updated'
  | 'member.revoked'
  | 'member.restored'
  | 'member.removed'
  | 'member.left'
  | 'group.created'
  | 'group.updated'
  | 'group.deleted'
  | 'collection.created'
  | 'collection.updated'
  | 'collection.deleted'
  | 'user.email_verified'
  | 'user.login_2fa_failed'
  | 'user.2fa_totp_enabled'
  | 'user.2fa_totp_disabled'
  | 'user.2fa_key_added'
  | 'user.2fa_key_removed'
  | 'user.2fa_recovery_codes_generated'
  | 'user.2fa_recovery_code_used'
  | 'org.policy_updated'
  | 'org.recovery_kit_created'
  | 'org.recovery_kit_deleted'
  | 'org.break_glass_recovered'
  | 'member.recovery_enrolled'
  | 'member.recovery_withdrawn'
  | 'member.account_recovered'
  | 'emergency.invited'
  | 'emergency.accepted'
  | 'emergency.confirmed'
  | 'emergency.recovery_initiated'
  | 'emergency.recovery_approved'
  | 'emergency.recovery_rejected'
  | 'emergency.revoked'
  | 'emergency.vault_accessed'
  | 'org.audit_exported'
  | 'org.compliance_report_generated'
  | 'org.log_destination_created'
  | 'org.log_destination_updated'
  | 'org.log_destination_deleted'
  | 'user.sso_login_failed'
  | 'user.sso_linked'
  | 'user.sso_provisioned'
  | 'org.sso_updated'
  | 'org.domain_added'
  | 'org.domain_verified'
  | 'org.domain_removed'
  | 'org.scim_token_created'
  | 'org.scim_token_revoked'
  | 'scim.user_provisioned'
  | 'scim.user_updated'
  | 'scim.user_deprovisioned'
  | 'scim.user_deleted'
  | 'scim.group_created'
  | 'scim.group_updated'
  | 'scim.group_deleted'
  | 'group.synced'
  | 'device.trusted'
  | 'device.approval_requested'
  | 'device.approved'
  | 'device.denied'
  | 'device.removed';

export interface AuditInput {
  userId: string | null;
  orgId?: string | null;
  action: AuditAction;
  targetType?: string | null;
  targetId?: string | null;
  metadata?: Record<string, unknown>;
}

interface ChainFields {
  userId: string | null;
  /** Omitted (not null) when absent so pre-Phase-2 events hash identically. */
  orgId?: string;
  action: string;
  targetType: string | null;
  targetId: string | null;
  ip: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
}

const GENESIS = Buffer.alloc(32);
const AUDIT_LOCK = 727002;

/** Deterministic JSON (sorted keys) so hashes can be recomputed by any verifier. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .sort()
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`)
    .join(',')}}`;
}

export function chainHash(prev: Buffer, fields: ChainFields): Buffer {
  return createHash('sha256').update(prev).update(canonical(fields)).digest();
}

/**
 * Appends an event. Must run inside a transaction: the advisory lock is held
 * until commit so events are chained in a strict order.
 */
export async function recordAudit(client: Queryable, req: FastifyRequest | null, input: AuditInput): Promise<void> {
  const fields: ChainFields = {
    userId: input.userId,
    orgId: input.orgId ?? undefined,
    action: input.action,
    targetType: input.targetType ?? null,
    targetId: input.targetId ?? null,
    ip: req?.ip ?? null,
    userAgent: req?.headers['user-agent']?.slice(0, 300) ?? null,
    metadata: input.metadata ?? {},
    createdAt: new Date().toISOString(),
  };
  await client.query('SELECT pg_advisory_xact_lock($1)', [AUDIT_LOCK]);
  const { rows } = await client.query<{ hash: Buffer }>('SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1');
  const prev = rows[0]?.hash ?? GENESIS;
  const hash = chainHash(prev, fields);

  // Tenant chain: same fields, linked only to the previous event of this org.
  let org: { seq: number; prev: Buffer; hash: Buffer } | null = null;
  if (fields.orgId) {
    const last = await client.query<{ org_seq: string; org_hash: Buffer }>(
      'SELECT org_seq, org_hash FROM audit_events WHERE org_id = $1 AND org_seq IS NOT NULL ORDER BY org_seq DESC LIMIT 1',
      [fields.orgId],
    );
    const seq = Number(last.rows[0]?.org_seq ?? 0) + 1;
    const orgPrev = last.rows[0]?.org_hash ?? GENESIS;
    org = { seq, prev: orgPrev, hash: orgChainHash(orgPrev, seq, fields) };
  }

  await client.query(
    `INSERT INTO audit_events (user_id, org_id, action, target_type, target_id, ip, user_agent, metadata, created_at, prev_hash, hash,
                               org_seq, org_prev_hash, org_hash)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
    [fields.userId, fields.orgId ?? null, fields.action, fields.targetType, fields.targetId, fields.ip, fields.userAgent, fields.metadata, fields.createdAt, prev, hash,
      org?.seq ?? null, org?.prev ?? null, org?.hash ?? null],
  );
}

export function orgChainHash(prev: Buffer, seq: number, fields: ChainFields): Buffer {
  return createHash('sha256').update(prev).update(`org-seq:${seq}|`).update(canonical(fields)).digest();
}

interface AuditRow {
  id: string;
  user_id: string | null;
  org_id: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  user_agent: string | null;
  metadata: Record<string, unknown>;
  created_at: Date;
}

const fieldsOf = (r: AuditRow): ChainFields => ({
  userId: r.user_id,
  orgId: r.org_id ?? undefined,
  action: r.action,
  targetType: r.target_type,
  targetId: r.target_id,
  ip: r.ip,
  userAgent: r.user_agent,
  metadata: r.metadata,
  createdAt: new Date(r.created_at).toISOString(),
});

export interface OrgVerifyResult {
  ok: boolean;
  checked: number;
  /** Org events recorded before per-org chaining existed (covered by the global chain only). */
  legacy: number;
  head: { seq: number; hash: string } | null;
  brokenAtSeq?: number;
  reason?: string;
}

/**
 * Verifies one organization's chain: contiguous sequence numbers, links and
 * contents. Publish or stream the head hash to detect truncation of the tail.
 */
export async function verifyOrgChain(db: Queryable, orgId: string, pageSize = 5000): Promise<OrgVerifyResult> {
  const legacy = Number(
    (await db.query<{ n: string }>('SELECT count(*) AS n FROM audit_events WHERE org_id = $1 AND org_seq IS NULL', [orgId])).rows[0]!.n,
  );
  let prev: Buffer = GENESIS;
  let expectedSeq = 1;
  let checked = 0;
  for (;;) {
    const { rows } = await db.query<AuditRow & { org_seq: string; org_prev_hash: Buffer; org_hash: Buffer }>(
      `SELECT id, user_id, org_id, action, target_type, target_id, ip, user_agent, metadata, created_at, org_seq, org_prev_hash, org_hash
         FROM audit_events WHERE org_id = $1 AND org_seq >= $2 ORDER BY org_seq LIMIT $3`,
      [orgId, expectedSeq, pageSize],
    );
    if (rows.length === 0) {
      return { ok: true, checked, legacy, head: checked ? { seq: expectedSeq - 1, hash: prev.toString('hex') } : null };
    }
    for (const r of rows) {
      const seq = Number(r.org_seq);
      const fail = (reason: string): OrgVerifyResult => ({ ok: false, checked, legacy, head: null, brokenAtSeq: seq, reason });
      if (seq !== expectedSeq) return fail(`event #${expectedSeq} is missing (deleted)`);
      if (!Buffer.from(r.org_prev_hash).equals(prev)) return fail('link to the previous event is broken');
      const expected = orgChainHash(prev, seq, fieldsOf(r));
      if (!expected.equals(Buffer.from(r.org_hash))) return fail('event contents were modified');
      prev = expected;
      expectedSeq++;
      checked++;
    }
  }
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  brokenAt?: number;
  reason?: string;
}

/** Recomputes the full chain. Streams in pages to keep memory flat. */
export async function verifyAuditChain(db: Db, pageSize = 5000): Promise<VerifyResult> {
  let prev: Buffer = GENESIS;
  let lastId = 0;
  let checked = 0;
  for (;;) {
    const { rows } = await db.query(
      `SELECT id, user_id, org_id, action, target_type, target_id, ip, user_agent, metadata, created_at, prev_hash, hash
         FROM audit_events WHERE id > $1 ORDER BY id LIMIT $2`,
      [lastId, pageSize],
    );
    if (rows.length === 0) return { ok: true, checked };
    for (const r of rows) {
      if (!Buffer.from(r.prev_hash).equals(prev)) {
        return { ok: false, checked, brokenAt: Number(r.id), reason: 'prev_hash does not match preceding event (event removed or reordered)' };
      }
      const expected = chainHash(prev, fieldsOf(r));
      if (!expected.equals(Buffer.from(r.hash))) {
        return { ok: false, checked, brokenAt: Number(r.id), reason: 'event contents were modified' };
      }
      prev = expected;
      lastId = Number(r.id);
      checked++;
    }
  }
}
