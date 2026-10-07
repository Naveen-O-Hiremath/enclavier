import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  ssoDiscoverRequest,
  ssoExchangeRequest,
  ssoLinkRequest,
  ssoProvisionRequest,
  ssoStartRequest,
  type LoginResponse,
  type SsoDiscovery,
  type SsoExchangeResult,
} from '@enclavier/shared';
import { requireAuth } from '../app';
import { recordAudit } from '../audit';
import { withOrgTx, withTx, type Queryable } from '../db';
import { conflict, forbidden, HttpError, notFound, parse, unauthorized } from '../errors';
import { completeLogin, issueTokens } from '../login';
import { hashAuthSecret, newRefreshToken, sha256 } from '../security';
import { beginOidc, beginSaml, completeOidc, completeSaml, newState, samlMetadata, SsoError, type SsoIdentity } from '../sso/protocols';
import { findSsoOrg, isVerifiedDomain, loadSsoConfig, type SsoConfigRow } from '../sso/store';
import { createLoginChallenge } from '../twofactor';
import { findUser, toKeys, toProfile, type UserRow } from '../users';

const TXN_TTL_MINUTES = 10;
const TOKEN_TTL = 15 * 60;
const orgParam = z.object({ orgId: z.string().uuid() });
const samlBody = z.object({ SAMLResponse: z.string().min(1).max(2_000_000), RelayState: z.string().max(200).optional() });
const ssoRateLimit = { rateLimit: { max: 20, timeWindow: '1 minute' } };

const b64sha256 = (s: string) => createHash('sha256').update(s).digest('base64url');

function sameString(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/**
 * Keeps the membership side of an SSO sign-in current: records the login,
 * accepts a pending invitation for this address and syncs IdP-managed groups.
 */
async function onSsoSignIn(app: FastifyInstance, req: FastifyRequest, cfg: SsoConfigRow, user: { id: string; email: string }, id: SsoIdentity) {
  await withOrgTx(app.db, { orgId: cfg.orgId, userId: user.id }, async (client) => {
    await client.query('UPDATE sso_identities SET last_login_at = now(), email = $3 WHERE org_id = $1 AND user_id = $2', [cfg.orgId, user.id, id.email]);
    const invited = await client.query<{ id: string }>(
      `UPDATE org_members SET user_id = $3, status = 'accepted', invite_token_hash = NULL, invite_expires_at = NULL, updated_at = now()
        WHERE org_id = $1 AND email = $2 AND status = 'invited'
          AND NOT EXISTS (SELECT 1 FROM org_members x WHERE x.org_id = $1 AND x.user_id = $3)
        RETURNING id`,
      [cfg.orgId, user.email, user.id],
    );
    if (invited.rows[0]) {
      await recordAudit(client, req, { orgId: cfg.orgId, userId: user.id, action: 'member.accepted', targetType: 'member', targetId: invited.rows[0].id, metadata: { via: 'sso' } });
    }
    if (cfg.groupSync) await syncGroups(client, req, cfg.orgId, user.id, id.groups);
  });
}

/** Membership of groups that have an IdP external ID mirrors the groups claim; other groups are untouched. */
export async function syncGroups(client: Queryable, req: FastifyRequest, orgId: string, userId: string, claimed: string[]) {
  const member = (await client.query<{ id: string }>('SELECT id FROM org_members WHERE org_id = $1 AND user_id = $2', [orgId, userId])).rows[0];
  if (!member) return;
  const wanted = new Set(claimed.map((g) => g.toLowerCase()));
  const { rows } = await client.query<{ id: string; external_id: string; is_member: boolean }>(
    `SELECT g.id, g.external_id, EXISTS (SELECT 1 FROM group_members gm WHERE gm.group_id = g.id AND gm.member_id = $2) AS is_member
       FROM groups g WHERE g.org_id = $1 AND g.external_id IS NOT NULL`,
    [orgId, member.id],
  );
  const add = rows.filter((g) => wanted.has(g.external_id.toLowerCase()) && !g.is_member).map((g) => g.id);
  const remove = rows.filter((g) => !wanted.has(g.external_id.toLowerCase()) && g.is_member).map((g) => g.id);
  if (add.length) {
    await client.query('INSERT INTO group_members (group_id, member_id, org_id) SELECT unnest($1::uuid[]), $2, $3 ON CONFLICT DO NOTHING', [add, member.id, orgId]);
  }
  if (remove.length) {
    await client.query('DELETE FROM group_members WHERE member_id = $1 AND group_id = ANY($2::uuid[])', [member.id, remove]);
  }
  if (add.length || remove.length) {
    await recordAudit(client, req, { orgId, userId, action: 'group.synced', targetType: 'member', targetId: member.id, metadata: { added: add, removed: remove } });
  }
}

export async function ssoRoutes(app: FastifyInstance): Promise<void> {
  const { db, config, secrets, purposeTokens } = app;
  const webBase = config.PUBLIC_URL.replace(/\/$/, '');

  // IdPs POST SAML responses as an HTML form.
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string', bodyLimit: 2_500_000 }, (_req, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(body as string)));
  });

  const toWeb = (reply: FastifyReply, fragment: Record<string, string>) =>
    reply.redirect(`${webBase}/sso/callback#${new URLSearchParams(fragment).toString()}`, 303);

  // ---- starting a sign-in ----------------------------------------------------------------

  app.post('/discover', { config: ssoRateLimit }, async (req): Promise<SsoDiscovery> => {
    const body = parse(ssoDiscoverRequest, req.body);
    const cfg = await findSsoOrg(db, secrets, body);
    return cfg ? { available: true, orgName: cfg.orgName, identifier: cfg.identifier } : { available: false };
  });

  app.post('/start', { config: ssoRateLimit }, async (req) => {
    const body = parse(ssoStartRequest, req.body);
    const cfg = await findSsoOrg(db, secrets, body);
    if (!cfg) throw notFound('Single sign-on is not set up for this organization or e-mail domain');
    const state = newState();
    try {
      if (cfg.settings.type === 'oidc') {
        const { url, nonce, codeVerifier } = await beginOidc(app, cfg.settings, state);
        await db.query(
          `INSERT INTO sso_transactions (id, org_id, binding_hash, nonce, code_verifier, expires_at)
           VALUES ($1, $2, $3, $4, $5, now() + make_interval(mins => $6))`,
          [state, cfg.orgId, body.binding, nonce, codeVerifier, TXN_TTL_MINUTES],
        );
        return { redirectUrl: url };
      }
      const { url, requestId } = await beginSaml(app, cfg.orgId, cfg.settings, state);
      await db.query(
        `INSERT INTO sso_transactions (id, org_id, binding_hash, saml_request_id, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(mins => $5))`,
        [state, cfg.orgId, body.binding, requestId, TXN_TTL_MINUTES],
      );
      return { redirectUrl: url };
    } catch (err) {
      if (err instanceof SsoError) throw new HttpError(502, 'sso_unavailable', err.message);
      throw err;
    }
  });

  // ---- IdP callbacks ----------------------------------------------------------------------

  async function openTransaction(state: string, orgId?: string) {
    const { rows } = await db.query(
      `SELECT * FROM sso_transactions WHERE id = $1 AND consumed_at IS NULL AND result IS NULL AND expires_at > now()`,
      [state],
    );
    const txn = rows[0];
    if (!txn || (orgId && txn.org_id !== orgId)) return null;
    return txn as { id: string; org_id: string; nonce: string; code_verifier: string; saml_request_id: string };
  }

  async function finishCallback(reply: FastifyReply, req: FastifyRequest, txnId: string, orgId: string, verify: (cfg: SsoConfigRow) => Promise<SsoIdentity>) {
    const cfg = await loadSsoConfig(db, secrets, orgId);
    if (!cfg?.enabled) return toWeb(reply, { error: 'Single sign-on is turned off for this organization' });
    let identity: SsoIdentity;
    try {
      identity = await verify(cfg);
    } catch (err) {
      const message = err instanceof SsoError ? err.message : 'The sign-in could not be verified';
      if (!(err instanceof SsoError)) req.log.error({ err }, 'SSO callback failed');
      await withTx(db, async (client) => {
        await client.query('UPDATE sso_transactions SET consumed_at = now() WHERE id = $1', [txnId]);
        await recordAudit(client, req, { orgId, userId: null, action: 'user.sso_login_failed', targetType: 'org', targetId: orgId, metadata: { reason: message.slice(0, 300) } });
      });
      return toWeb(reply, { error: message });
    }
    const code = newRefreshToken();
    const res = await db.query('UPDATE sso_transactions SET result = $2, code_hash = $3 WHERE id = $1 AND result IS NULL AND consumed_at IS NULL', [
      txnId,
      identity,
      sha256(code),
    ]);
    if (!res.rowCount) return toWeb(reply, { error: 'This sign-in was already used. Start again.' });
    return toWeb(reply, { code });
  }

  app.get('/oidc/callback', { config: ssoRateLimit }, async (req, reply) => {
    const query = parse(z.record(z.string().max(4000)), req.query);
    const txn = query.state ? await openTransaction(query.state) : null;
    if (!txn || !txn.code_verifier) return toWeb(reply, { error: 'This sign-in expired or was already used. Start again.' });
    if (query.error) {
      await db.query('UPDATE sso_transactions SET consumed_at = now() WHERE id = $1', [txn.id]);
      return toWeb(reply, { error: `The identity provider returned: ${(query.error_description || query.error).slice(0, 300)}` });
    }
    return finishCallback(reply, req, txn.id, txn.org_id, (cfg) => {
      if (cfg.settings.type !== 'oidc') throw new SsoError('This organization no longer uses OpenID Connect');
      return completeOidc(app, cfg.settings, { id: txn.id, nonce: txn.nonce, codeVerifier: txn.code_verifier }, query);
    });
  });

  app.post('/saml/:orgId/acs', { config: ssoRateLimit }, async (req, reply) => {
    const { orgId } = parse(orgParam, req.params);
    const body = parse(samlBody, req.body);
    // IdP-initiated sign-ins (no RelayState) are refused: they can't be bound to a browser.
    const txn = body.RelayState ? await openTransaction(body.RelayState, orgId) : null;
    if (!txn || !txn.saml_request_id) return toWeb(reply, { error: 'Start the sign-in from Enclavier (identity-provider initiated sign-in is not supported).' });
    return finishCallback(reply, req, txn.id, orgId, (cfg) => {
      if (cfg.settings.type !== 'saml') throw new SsoError('This organization no longer uses SAML');
      return completeSaml(app, orgId, cfg.settings, txn.saml_request_id, body);
    });
  });

  app.get('/saml/:orgId/metadata', async (req, reply) => {
    const { orgId } = parse(orgParam, req.params);
    return reply.type('application/samlmetadata+xml').send(samlMetadata(app, orgId));
  });

  // ---- completing the sign-in in the web vault -------------------------------------------------

  app.post('/exchange', { config: ssoRateLimit }, async (req): Promise<SsoExchangeResult> => {
    const body = parse(ssoExchangeRequest, req.body);
    // Consumed on first use, whatever the outcome: codes can't be retried or replayed.
    const { rows } = await db.query(
      `UPDATE sso_transactions SET consumed_at = now()
        WHERE code_hash = $1 AND consumed_at IS NULL AND result IS NOT NULL AND expires_at > now()
        RETURNING org_id, binding_hash, result`,
      [sha256(body.code)],
    );
    const txn = rows[0] as { org_id: string; binding_hash: string; result: SsoIdentity } | undefined;
    if (!txn) throw unauthorized('This sign-in expired or was already used. Start again.');
    if (!sameString(b64sha256(body.bindingSecret), txn.binding_hash)) {
      throw unauthorized('This sign-in was started in a different browser. Start again from this window.');
    }
    const cfg = await loadSsoConfig(db, secrets, txn.org_id);
    if (!cfg?.enabled) throw forbidden('Single sign-on is turned off for this organization');
    const identity = txn.result;
    const org = { id: cfg.orgId, name: cfg.orgName, identifier: cfg.identifier };

    const linked = await db.query<{ user_id: string }>('SELECT user_id FROM sso_identities WHERE org_id = $1 AND subject = $2', [cfg.orgId, identity.subject]);
    let user: UserRow | undefined = linked.rows[0] ? await findUser(db, 'id', linked.rows[0].user_id) : undefined;

    if (!user) {
      const existing = await findUser(db, 'email', identity.email);
      const verifiedDomain = await isVerifiedDomain(db, cfg.orgId, identity.email);
      if (existing) {
        if (!verifiedDomain) {
          // The org doesn't own this address: the account holder must prove it with their master password.
          const linkToken = await purposeTokens.sign('sso-link', existing.id, { orgId: cfg.orgId, subject: identity.subject, email: identity.email, groups: JSON.stringify(identity.groups) }, TOKEN_TTL);
          return { status: 'link_required', email: identity.email, orgName: cfg.orgName, linkToken, org };
        }
        await db.query('INSERT INTO sso_identities (org_id, subject, user_id, email) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING', [
          cfg.orgId,
          identity.subject,
          existing.id,
          identity.email,
        ]);
        await withTx(db, (client) =>
          recordAudit(client, req, { orgId: cfg.orgId, userId: existing.id, action: 'user.sso_linked', targetType: 'user', targetId: existing.id, metadata: { via: 'verified_domain' } }),
        );
        user = existing;
      } else {
        const invited = await db.query('SELECT 1 FROM org_members WHERE org_id = $1 AND email = $2 AND status = $3', [cfg.orgId, identity.email, 'invited']);
        if (!cfg.jitProvisioning || (!verifiedDomain && !invited.rowCount)) {
          throw forbidden(`There is no Enclavier account for ${identity.email}. Ask an administrator of ${cfg.orgName} to invite you.`);
        }
        const provisionToken = await purposeTokens.sign('sso-provision', identity.email, { orgId: cfg.orgId, subject: identity.subject, name: identity.name, groups: JSON.stringify(identity.groups) }, TOKEN_TTL);
        return { status: 'provision', email: identity.email, name: identity.name, orgName: cfg.orgName, provisionToken, org };
      }
    }

    if (user.locked_until && user.locked_until > new Date()) throw new HttpError(429, 'locked', 'Too many failed attempts. Try again later.');
    await onSsoSignIn(app, req, cfg, user, identity);

    let replacesSessionId: string | undefined;
    if (body.previousRefreshToken) {
      const s = await db.query<{ id: string }>('SELECT id FROM sessions WHERE token_hash = $1 AND user_id = $2 AND revoked_at IS NULL', [
        sha256(body.previousRefreshToken),
        user.id,
      ]);
      replacesSessionId = s.rows[0]?.id;
    }
    // Enclavier's own second factor still applies on top of the IdP's.
    const ctx = { deviceName: body.deviceName, deviceId: body.deviceId, replacesSessionId, orgId: cfg.orgId };
    const challenge = await createLoginChallenge(app, user, ctx);
    if (challenge) return { status: 'two_factor', challenge, org };
    return { status: 'authenticated', login: await completeLogin(app, user, req, { ...ctx, method: 'sso' }), org };
  });

  /** Links an existing account after its owner signed in with their master password. */
  app.post('/link', { preHandler: app.authenticate, config: ssoRateLimit }, async (req, reply) => {
    const { userId } = requireAuth(req);
    const { linkToken } = parse(ssoLinkRequest, req.body);
    let verified;
    try {
      verified = await purposeTokens.verify('sso-link', linkToken);
    } catch {
      throw unauthorized('This link request expired. Sign in with SSO again.');
    }
    if (verified.sub !== userId) throw forbidden('Sign in with the account that matches your SSO identity');
    const orgId = String(verified.claims.orgId);
    const cfg = await loadSsoConfig(db, secrets, orgId);
    if (!cfg?.enabled) throw forbidden('Single sign-on is turned off for this organization');
    const identity: SsoIdentity = {
      subject: String(verified.claims.subject),
      email: String(verified.claims.email),
      name: '',
      groups: JSON.parse(String(verified.claims.groups || '[]')) as string[],
    };
    const user = (await findUser(db, 'id', userId))!;
    await withTx(db, async (client) => {
      await client.query(
        `INSERT INTO sso_identities (org_id, subject, user_id, email) VALUES ($1, $2, $3, $4)
         ON CONFLICT (org_id, user_id) DO UPDATE SET subject = EXCLUDED.subject, email = EXCLUDED.email`,
        [orgId, identity.subject, userId, identity.email],
      );
      await recordAudit(client, req, { orgId, userId, action: 'user.sso_linked', targetType: 'user', targetId: userId, metadata: { via: 'master_password' } });
    });
    await onSsoSignIn(app, req, cfg, user, identity);
    return reply.status(204).send();
  });

  /** Just-in-time provisioning: the client created the account keys under a new master password. */
  app.post('/provision', { config: ssoRateLimit }, async (req, reply) => {
    const body = parse(ssoProvisionRequest, req.body);
    let verified;
    try {
      verified = await purposeTokens.verify('sso-provision', body.provisionToken);
    } catch {
      throw unauthorized('This sign-up expired. Sign in with SSO again.');
    }
    const email = verified.sub;
    const orgId = String(verified.claims.orgId);
    const cfg = await loadSsoConfig(db, secrets, orgId);
    if (!cfg?.enabled || !cfg.jitProvisioning) throw forbidden('Just-in-time provisioning is turned off for this organization');
    const identity: SsoIdentity = {
      subject: String(verified.claims.subject),
      email,
      name: String(verified.claims.name || ''),
      groups: JSON.parse(String(verified.claims.groups || '[]')) as string[],
    };
    const userId = randomUUID();
    const authHash = await hashAuthSecret(body.authHash);
    const response = await withTx(db, async (client): Promise<LoginResponse> => {
      const inserted = await client.query<UserRow>(
        `INSERT INTO users (id, email, name, auth_hash, kdf, salt, protected_user_key, public_key, protected_private_key, email_verified_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
         ON CONFLICT (email) DO NOTHING RETURNING *`,
        [userId, email, body.name, authHash, body.kdf, body.salt, body.protectedUserKey, body.publicKey, body.protectedPrivateKey],
      );
      const user = inserted.rows[0];
      if (!user) throw conflict('An account with this e-mail already exists. Sign in with SSO again to link it.');
      await client.query('INSERT INTO sso_identities (org_id, subject, user_id, email, last_login_at) VALUES ($1, $2, $3, $4, now())', [
        orgId,
        identity.subject,
        userId,
        email,
      ]);
      await recordAudit(client, req, { userId, action: 'user.register', targetType: 'user', targetId: userId, metadata: { via: 'sso' } });
      await recordAudit(client, req, { orgId, userId, action: 'user.sso_provisioned', targetType: 'user', targetId: userId, metadata: { email } });
      const tokenSet = await issueTokens(app, client, req, userId, body.deviceName);
      return { ...tokenSet, profile: toProfile(user), keys: toKeys(user), deviceKey: null };
    });
    // Joins the organization: accepts an invitation, or (verified domain) adds a new member awaiting confirmation.
    await withOrgTx(db, { orgId, userId }, async (client) => {
      const existing = await client.query('SELECT 1 FROM org_members WHERE org_id = $1 AND email = $2', [orgId, email]);
      if (!existing.rowCount) {
        const memberId = randomUUID();
        await client.query(`INSERT INTO org_members (id, org_id, user_id, email, role, status) VALUES ($1, $2, $3, $4, 'member', 'accepted')`, [
          memberId,
          orgId,
          userId,
          email,
        ]);
        await recordAudit(client, req, { orgId, userId, action: 'member.accepted', targetType: 'member', targetId: memberId, metadata: { via: 'sso_jit' } });
      }
    });
    await onSsoSignIn(app, req, cfg, { id: userId, email }, identity);
    return reply.status(201).send(response);
  });
}
