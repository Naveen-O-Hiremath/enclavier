import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  accountRecoveryRequest,
  breakGlassRequest,
  recoveryEnrollRequest,
  recoveryKitRequest,
  updatePolicyRequest,
  type MemberRecoveryMaterial,
  type OrgPolicies,
  type PolicyType,
  type RecoveryKitInfo,
} from '@enclavier/shared';
import { requireAuth } from '../app';
import { recordAudit, type AuditInput } from '../audit';
import { withOrgTx, type Queryable } from '../db';
import { badRequest, forbidden, notFound, parse } from '../errors';
import { loadMembership, loadPolicies, requireActiveMember, requireAdmin, requireOwner, userHasTwoFactor } from '../orgs/access';
import { hashAuthSecret, sha256 } from '../security';
import { notify } from '../twofactor';

const orgParam = z.object({ orgId: z.string().uuid() });
const memberParam = orgParam.extend({ memberId: z.string().uuid() });

export function policiesToDto(policies: Awaited<ReturnType<typeof loadPolicies>>): OrgPolicies {
  const recovery = policies.get('account_recovery');
  const on = (type: PolicyType) => {
    const p = policies.get(type);
    return p?.enabled ? p.data : null;
  };
  const mp = on('master_password');
  const gen = on('password_generator');
  const vt = on('vault_timeout');
  const cb = on('clipboard');
  return {
    require2fa: !!policies.get('require_2fa')?.enabled,
    accountRecovery: !!recovery?.enabled,
    accountRecoveryAutoEnroll: !!recovery?.enabled && recovery.data.autoEnroll === true,
    masterPassword: mp ? { minLength: Number(mp.minLength), minScore: Number(mp.minScore) } : null,
    passwordGenerator: gen
      ? {
          minLength: Number(gen.minLength),
          requireUppercase: !!gen.requireUppercase,
          requireLowercase: !!gen.requireLowercase,
          requireDigits: !!gen.requireDigits,
          requireSymbols: !!gen.requireSymbols,
        }
      : null,
    vaultTimeout: vt ? { maxMinutes: Number(vt.maxMinutes) } : null,
    clipboard: cb ? { maxSeconds: Number(cb.maxSeconds) } : null,
    disableExport: !!policies.get('disable_export')?.enabled,
  };
}

export async function orgRecoveryRoutes(app: FastifyInstance): Promise<void> {
  const { db } = app;
  app.addHook('preHandler', app.authenticate);

  const audit = (client: Queryable, req: FastifyRequest, orgId: string, input: Omit<AuditInput, 'userId' | 'orgId'>) =>
    recordAudit(client, req, { ...input, orgId, userId: req.auth?.userId ?? null });

  // ---- policies ----------------------------------------------------------------------

  app.get('/orgs/:orgId/policies', async (req): Promise<OrgPolicies> => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    return withOrgTx(db, { orgId, userId }, async (client) => {
      await loadMembership(client, orgId, userId);
      return policiesToDto(await loadPolicies(client, orgId));
    });
  });

  app.put('/orgs/:orgId/policies', async (req): Promise<OrgPolicies> => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    const body = parse(updatePolicyRequest, req.body);
    return withOrgTx(db, { orgId, userId }, async (client) => {
      await requireAdmin(client, orgId, userId);

      if (body.type === 'require_2fa') {
        if (body.enabled && !(await userHasTwoFactor(client, userId))) {
          throw badRequest('Turn on two-step login for your own account before requiring it for everyone.');
        }
        await client.query(
          `INSERT INTO org_policies (org_id, type, enabled) VALUES ($1, 'require_2fa', $2)
           ON CONFLICT (org_id, type) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now()`,
          [orgId, body.enabled],
        );
      } else if (body.type === 'account_recovery') {
        if (body.enabled) {
          const { rows } = await client.query<{ recovery_public_key: string | null }>(
            'SELECT recovery_public_key FROM organizations WHERE id = $1',
            [orgId],
          );
          if (!rows[0]!.recovery_public_key) {
            if (!body.recoveryKeyPair) throw badRequest('A recovery key pair is required the first time account recovery is enabled');
            await client.query('UPDATE organizations SET recovery_public_key = $2, recovery_private_key = $3 WHERE id = $1', [
              orgId,
              body.recoveryKeyPair.publicKey,
              body.recoveryKeyPair.protectedPrivateKey,
            ]);
          }
        } else {
          // Turning recovery off destroys every escrowed key, so admins can no longer reset anyone.
          await client.query('UPDATE org_members SET recovery_key = NULL, recovery_enrolled_at = NULL WHERE org_id = $1', [orgId]);
        }
        await client.query(
          `INSERT INTO org_policies (org_id, type, enabled, data) VALUES ($1, 'account_recovery', $2, $3)
           ON CONFLICT (org_id, type) DO UPDATE SET enabled = EXCLUDED.enabled, data = EXCLUDED.data, updated_at = now()`,
          [orgId, body.enabled, { autoEnroll: body.enabled && body.autoEnroll }],
        );
      } else {
        // Generic policies: settings live in the jsonb data column.
        const { type, enabled, ...data } = body;
        await client.query(
          `INSERT INTO org_policies (org_id, type, enabled, data) VALUES ($1, $2, $3, $4)
           ON CONFLICT (org_id, type) DO UPDATE SET enabled = EXCLUDED.enabled, data = EXCLUDED.data, updated_at = now()`,
          [orgId, type, enabled, data],
        );
      }
      await audit(client, req, orgId, { action: 'org.policy_updated', targetType: 'policy', targetId: body.type, metadata: { ...body, recoveryKeyPair: undefined } });
      return policiesToDto(await loadPolicies(client, orgId));
    });
  });

  // ---- account recovery: member enrollment ----------------------------------------------

  app.post('/orgs/:orgId/recovery/enroll', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    const { recoveryKey } = parse(recoveryEnrollRequest, req.body);
    await withOrgTx(db, { orgId, userId }, async (client) => {
      const m = await requireActiveMember(client, orgId, userId);
      if (!(await loadPolicies(client, orgId)).get('account_recovery')?.enabled) throw badRequest('Account recovery is not enabled');
      await client.query('UPDATE org_members SET recovery_key = $2, recovery_enrolled_at = now() WHERE id = $1', [m.id, recoveryKey]);
      await audit(client, req, orgId, { action: 'member.recovery_enrolled', targetType: 'member', targetId: m.id });
    });
    return reply.status(204).send();
  });

  app.post('/orgs/:orgId/recovery/withdraw', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    await withOrgTx(db, { orgId, userId }, async (client) => {
      const m = await loadMembership(client, orgId, userId);
      const policy = (await loadPolicies(client, orgId)).get('account_recovery');
      if (policy?.enabled && policy.data.autoEnroll === true) {
        throw forbidden('Your organization requires account recovery enrollment');
      }
      await client.query('UPDATE org_members SET recovery_key = NULL, recovery_enrolled_at = NULL WHERE id = $1', [m.id]);
      await audit(client, req, orgId, { action: 'member.recovery_withdrawn', targetType: 'member', targetId: m.id });
    });
    return reply.status(204).send();
  });

  // ---- account recovery: admin-assisted reset ---------------------------------------------

  async function recoverableTarget(client: Queryable, orgId: string, actorId: string, memberId: string) {
    const actor = await requireAdmin(client, orgId, actorId);
    if (!(await loadPolicies(client, orgId)).get('account_recovery')?.enabled) throw badRequest('Account recovery is not enabled');
    const { rows } = await client.query(
      `SELECT m.id, m.user_id, m.role, m.status, m.revoked_at, m.recovery_key, u.email, u.name
         FROM org_members m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = $1 AND m.id = $2`,
      [orgId, memberId],
    );
    const t = rows[0];
    if (!t) throw notFound('Member not found');
    if (t.id === actor.id) throw badRequest('Use your own master password settings instead');
    if (t.role === 'owner' && actor.role !== 'owner') throw forbidden('Only owners can recover owner accounts');
    if (t.status !== 'confirmed' || t.revoked_at) throw badRequest('Only active members can be recovered');
    if (!t.recovery_key) throw badRequest('This member has not enrolled in account recovery');
    return t as { id: string; user_id: string; recovery_key: string; email: string; name: string };
  }

  app.get('/orgs/:orgId/members/:memberId/recovery', async (req): Promise<MemberRecoveryMaterial> => {
    const { userId } = requireAuth(req);
    const { orgId, memberId } = parse(memberParam, req.params);
    return withOrgTx(db, { orgId, userId }, async (client) => {
      const t = await recoverableTarget(client, orgId, userId, memberId);
      const { rows } = await client.query<{ recovery_private_key: string }>('SELECT recovery_private_key FROM organizations WHERE id = $1', [orgId]);
      return { userId: t.user_id, recoveryKey: t.recovery_key, protectedRecoveryPrivateKey: rows[0]!.recovery_private_key };
    });
  });

  app.post('/orgs/:orgId/members/:memberId/recover', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { userId } = requireAuth(req);
    const { orgId, memberId } = parse(memberParam, req.params);
    const body = parse(accountRecoveryRequest, req.body);
    const authHash = await hashAuthSecret(body.authHash);
    const target = await withOrgTx(db, { orgId, userId }, async (client) => {
      const t = await recoverableTarget(client, orgId, userId, memberId);
      await client.query(
        `UPDATE users SET auth_hash = $2, kdf = $3, salt = $4, protected_user_key = $5, force_password_change = true,
                failed_logins = 0, locked_until = NULL, updated_at = now()
          WHERE id = $1`,
        [t.user_id, authHash, body.kdf, body.salt, body.protectedUserKey],
      );
      // Every existing session belongs to whoever knew the old password: end them all.
      await client.query('UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL', [t.user_id]);
      await audit(client, req, orgId, { action: 'member.account_recovered', targetType: 'member', targetId: t.id, metadata: { email: t.email } });
      const org = (await client.query<{ name: string }>('SELECT name FROM organizations WHERE id = $1', [orgId])).rows[0]!;
      return { ...t, orgName: org.name };
    });
    void notify(app, target.email, 'Your Enclavier master password was reset by an administrator', [
      `An administrator of **${target.orgName}** reset the master password for your Enclavier account using account recovery.`,
      'They will give you a temporary password. You will be asked to choose a new master password when you sign in. All your devices were signed out.',
      'If you did not ask for this, contact your security team immediately.',
    ]);
    return reply.status(204).send();
  });

  // ---- break-glass recovery kit (Shamir shares of the org key) ---------------------------------

  app.get('/orgs/:orgId/recovery-kit', async (req): Promise<RecoveryKitInfo> => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    return withOrgTx(db, { orgId, userId }, async (client) => {
      await requireAdmin(client, orgId, userId);
      const { rows } = await client.query(
        'SELECT break_glass_shares, break_glass_threshold, break_glass_created_at FROM organizations WHERE id = $1',
        [orgId],
      );
      const r = rows[0]!;
      return {
        exists: !!r.break_glass_created_at,
        shares: r.break_glass_shares,
        threshold: r.break_glass_threshold,
        createdAt: r.break_glass_created_at?.toISOString() ?? null,
      };
    });
  });

  app.post('/orgs/:orgId/recovery-kit', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    const body = parse(recoveryKitRequest, req.body);
    if (body.threshold > body.shares) throw badRequest('Threshold cannot exceed the number of shares');
    await withOrgTx(db, { orgId, userId }, async (client) => {
      await requireOwner(client, orgId, userId);
      await client.query(
        `UPDATE organizations SET break_glass_verifier_hash = $2, break_glass_shares = $3, break_glass_threshold = $4,
                break_glass_created_at = now() WHERE id = $1`,
        [orgId, sha256(body.verifier), body.shares, body.threshold],
      );
      await audit(client, req, orgId, { action: 'org.recovery_kit_created', targetType: 'org', targetId: orgId, metadata: { shares: body.shares, threshold: body.threshold } });
    });
    return reply.status(204).send();
  });

  app.delete('/orgs/:orgId/recovery-kit', async (req, reply) => {
    const { userId } = requireAuth(req);
    const { orgId } = parse(orgParam, req.params);
    await withOrgTx(db, { orgId, userId }, async (client) => {
      await requireOwner(client, orgId, userId);
      await client.query(
        `UPDATE organizations SET break_glass_verifier_hash = NULL, break_glass_shares = NULL, break_glass_threshold = NULL,
                break_glass_created_at = NULL WHERE id = $1`,
        [orgId],
      );
      await audit(client, req, orgId, { action: 'org.recovery_kit_deleted', targetType: 'org', targetId: orgId });
    });
    return reply.status(204).send();
  });

  /**
   * Break-glass: whoever reconstructs the org key from enough shares proves it
   * with the verifier and becomes an owner. The server only compares hashes.
   */
  app.post('/orgs/break-glass', { config: { rateLimit: { max: 5, timeWindow: '1 hour' } } }, async (req) => {
    const { userId } = requireAuth(req);
    const body = parse(breakGlassRequest, req.body);
    const result = await withOrgTx(db, { orgId: body.orgId, userId }, async (client) => {
      const { rows } = await client.query<{ name: string; break_glass_verifier_hash: Buffer | null }>(
        'SELECT name, break_glass_verifier_hash FROM organizations WHERE id = $1',
        [body.orgId],
      );
      const org = rows[0];
      const expected = org?.break_glass_verifier_hash;
      if (!org || !expected || !timingSafeEqual(Buffer.from(expected), sha256(body.verifier))) {
        return null;
      }
      const user = (await client.query<{ email: string }>('SELECT email FROM users WHERE id = $1', [userId])).rows[0]!;
      const existing = await client.query<{ id: string }>('SELECT id FROM org_members WHERE org_id = $1 AND (user_id = $2 OR email = $3)', [
        body.orgId,
        userId,
        user.email,
      ]);
      const memberId = existing.rows[0]?.id ?? randomUUID();
      if (existing.rowCount) {
        await client.query(
          `UPDATE org_members SET user_id = $3, role = 'owner', status = 'confirmed', protected_org_key = $4, revoked_at = NULL,
                  invite_token_hash = NULL, invite_expires_at = NULL, updated_at = now()
            WHERE org_id = $1 AND id = $2`,
          [body.orgId, memberId, userId, body.protectedOrgKey],
        );
      } else {
        await client.query(
          `INSERT INTO org_members (id, org_id, user_id, email, role, status, protected_org_key)
           VALUES ($1, $2, $3, $4, 'owner', 'confirmed', $5)`,
          [memberId, body.orgId, userId, user.email, body.protectedOrgKey],
        );
      }
      await audit(client, req, body.orgId, { action: 'org.break_glass_recovered', targetType: 'member', targetId: memberId, metadata: { email: user.email } });
      const owners = await client.query<{ email: string }>(
        `SELECT email FROM org_members WHERE org_id = $1 AND role = 'owner' AND user_id <> $2 AND revoked_at IS NULL`,
        [body.orgId, userId],
      );
      return { orgName: org.name, email: user.email, owners: owners.rows.map((r) => r.email) };
    });
    if (!result) throw forbidden('These recovery shares do not match any organization recovery kit');
    for (const to of result.owners) {
      void notify(app, to, `Break-glass recovery used for ${result.orgName}`, [
        `**${result.email}** used the break-glass recovery kit of **${result.orgName}** and is now an owner.`,
        'If this was not planned, revoke their access immediately and create a new recovery kit.',
      ]);
    }
    return { orgId: body.orgId, orgName: result.orgName };
  });
}
