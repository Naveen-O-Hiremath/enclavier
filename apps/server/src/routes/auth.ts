import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  loginRequest,
  preloginRequest,
  refreshRequest,
  registerRequest,
  twoFactorLoginRequest,
  verifyEmailRequest,
  type LoginResponse,
  type LoginResult,
  type TokenResponse,
} from '@enclavier/shared';
import { recordAudit } from '../audit';
import { withTx, type Queryable } from '../db';
import { badRequest, conflict, forbidden, HttpError, parse, unauthorized } from '../errors';
import { completeLogin, issueTokens } from '../login';
import { dummyVerify, fakeSalt, hashAuthSecret, newRefreshToken, sha256, verifyAuthSecret } from '../security';
import { ssoEnforcedFor } from '../sso/store';
import { createLoginChallenge, issueEmailVerification, sendVerificationEmail, verifySecondFactor } from '../twofactor';
import { findUser, toKeys, toProfile, type UserRow } from '../users';

const DEFAULT_KDF = { algorithm: 'argon2id', memory: 65536, iterations: 3, parallelism: 4 } as const;
const MAX_FAILED_LOGINS = 10;
const LOCKOUT_MINUTES = 15;

const authRateLimit = { rateLimit: { max: 10, timeWindow: '1 minute' } };

/** No accounts yet: the installer's first user may register even when sign-ups are closed. */
export async function isFreshInstall(client: Queryable): Promise<boolean> {
  const { rows } = await client.query<{ any: boolean }>('SELECT EXISTS (SELECT 1 FROM users) AS any');
  return !rows[0]!.any;
}

export async function authRoutes(app: FastifyInstance): Promise<void> {
  const { db, config, tokens } = app;

  app.post('/prelogin', { config: authRateLimit }, async (req) => {
    const { email } = parse(preloginRequest, req.body);
    const { rows } = await db.query<{ kdf: typeof DEFAULT_KDF; salt: string }>('SELECT kdf, salt FROM users WHERE email = $1', [email]);
    const row = rows[0];
    // Unknown accounts get stable, plausible parameters so they can't be enumerated.
    return row ? { kdf: row.kdf, salt: row.salt } : { kdf: DEFAULT_KDF, salt: fakeSalt(config.SERVER_SECRET, email) };
  });

  app.post('/register', { config: authRateLimit }, async (req, reply) => {
    const body = parse(registerRequest, req.body);
    // A valid invitation token proves control of the address (it was e-mailed there).
    const invite = body.invite
      ? (
          await db.query(
            `SELECT email, invite_token_hash, invite_expires_at FROM org_members
              WHERE org_id = $1 AND id = $2 AND status = 'invited'`,
            [body.invite.orgId, body.invite.memberId],
          )
        ).rows[0]
      : undefined;
    const invitedAddress = !!(
      invite &&
      invite.email === body.email &&
      invite.invite_token_hash &&
      sha256(body.invite!.token).equals(invite.invite_token_hash) &&
      invite.invite_expires_at > new Date()
    );
    // Invited users may register even when open sign-up is off, but only for the invited address.
    // On a fresh install the very first account may also register (checked again under a lock below).
    const bootstrap = !config.SIGNUPS_ENABLED && !invitedAddress;
    if (bootstrap && !(await isFreshInstall(db))) {
      throw forbidden('Self-service sign-up is disabled on this server. Ask an administrator for an invitation.');
    }

    const userId = randomUUID();
    const authHash = await hashAuthSecret(body.authHash);
    const result = await withTx(db, async (client) => {
      if (bootstrap) {
        // Serialise concurrent first sign-ups: exactly one account can claim a fresh install.
        await client.query('SELECT pg_advisory_xact_lock(727002)');
        if (!(await isFreshInstall(client))) throw forbidden('Self-service sign-up is disabled on this server. Ask an administrator for an invitation.');
      }
      const inserted = await client.query<UserRow>(
        `INSERT INTO users (id, email, name, auth_hash, kdf, salt, protected_user_key, public_key, protected_private_key, email_verified_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (email) DO NOTHING
         RETURNING *`,
        [
          userId,
          body.email,
          body.name,
          authHash,
          body.kdf,
          body.salt,
          body.protectedUserKey,
          body.publicKey,
          body.protectedPrivateKey,
          invitedAddress ? new Date() : null,
        ],
      );
      const user = inserted.rows[0];
      if (!user) throw conflict('An account with this e-mail already exists');
      await recordAudit(client, req, { userId, action: 'user.register', targetType: 'user', targetId: userId });
      const verifyLink = invitedAddress ? null : await issueEmailVerification(client, config, userId);
      const tokenSet = await issueTokens(app, client, req, userId);
      const response: LoginResponse = { ...tokenSet, profile: toProfile(user), keys: toKeys(user) };
      return { response, verifyLink };
    });
    // Send after commit, so a link never points at a rolled-back account.
    if (result.verifyLink) await sendVerificationEmail(app, body.email, body.name, result.verifyLink);
    return reply.status(201).send(result.response);
  });

  async function registerFailure(user: UserRow, req: FastifyRequest, action: 'user.login_failed' | 'user.login_2fa_failed') {
    await withTx(db, async (client) => {
      await client.query(
        `UPDATE users SET failed_logins = failed_logins + 1,
           locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + make_interval(mins => $3) ELSE locked_until END
         WHERE id = $1`,
        [user.id, MAX_FAILED_LOGINS, LOCKOUT_MINUTES],
      );
      await recordAudit(client, req, { userId: user.id, action, targetType: 'user', targetId: user.id });
    });
  }

  function assertNotLocked(user: UserRow) {
    if (user.locked_until && user.locked_until > new Date()) {
      throw new HttpError(429, 'locked', 'Too many failed attempts. Try again later.');
    }
  }

  /**
   * Step 1: master password (proved via authHash). With 2FA enabled this returns
   * a short-lived challenge instead of tokens: the encrypted vault keys are only
   * released after the second factor.
   */
  app.post('/login', { config: authRateLimit }, async (req): Promise<LoginResult> => {
    const body = parse(loginRequest, req.body);
    const user = await findUser(db, 'email', body.email);
    if (!user) {
      await dummyVerify(body.authHash);
      throw unauthorized('Invalid e-mail or master password');
    }
    assertNotLocked(user);
    if (!(await verifyAuthSecret(body.authHash, user.auth_hash))) {
      await registerFailure(user, req, 'user.login_failed');
      throw unauthorized('Invalid e-mail or master password');
    }
    // Checked only after the password, so it reveals nothing to someone guessing e-mails.
    const ssoOrg = await ssoEnforcedFor(db, user.id);
    if (ssoOrg) {
      throw new HttpError(403, 'sso_required', `${ssoOrg.name} requires you to sign in with single sign-on (organization identifier: ${ssoOrg.identifier}).`);
    }
    const challenge = await createLoginChallenge(app, user, { deviceName: body.deviceName });
    return challenge ?? completeLogin(app, user, req, { deviceName: body.deviceName, method: 'password' });
  });

  /** Step 2: second factor (TOTP, security key / passkey, or a one-time recovery code). */
  app.post('/login/2fa', { config: authRateLimit }, async (req): Promise<LoginResponse> => {
    const body = parse(twoFactorLoginRequest, req.body);
    let verified;
    try {
      verified = await app.purposeTokens.verify('mfa', body.challengeToken);
    } catch {
      throw unauthorized('Your sign-in attempt expired. Enter your master password again.');
    }
    const user = await findUser(db, 'id', verified.sub);
    if (!user) throw unauthorized();
    assertNotLocked(user);
    const ok = await withTx(db, (client) =>
      verifySecondFactor(app, client, user, {
        method: body.method,
        code: body.code,
        webauthnResponse: body.webauthnResponse,
        webauthnChallenge: String(verified.claims.webauthnChallenge ?? ''),
      }),
    );
    if (!ok) {
      await registerFailure(user, req, 'user.login_2fa_failed');
      throw unauthorized(body.method === 'webauthn' ? 'Security key verification failed' : 'Invalid verification code');
    }
    if (body.method === 'recovery') {
      await withTx(db, (client) =>
        recordAudit(client, req, { userId: user.id, action: 'user.2fa_recovery_code_used', targetType: 'user', targetId: user.id }),
      );
    }
    const claim = (k: string) => String(verified.claims[k] || '') || undefined;
    const orgId = claim('orgId');
    return completeLogin(app, user, req, {
      deviceName: body.deviceName || claim('deviceName'),
      method: orgId ? `sso+${body.method}` : body.method,
      deviceId: claim('deviceId'),
      replacesSessionId: claim('replacesSessionId'),
      orgId,
    });
  });

  app.post('/verify-email', { config: authRateLimit }, async (req, reply) => {
    const { userId, token } = parse(verifyEmailRequest, req.body);
    await withTx(db, async (client) => {
      const res = await client.query(
        `UPDATE users SET email_verified_at = now(), email_verify_token_hash = NULL, email_verify_expires_at = NULL
          WHERE id = $1 AND email_verify_token_hash = $2 AND email_verify_expires_at > now()`,
        [userId, sha256(token)],
      );
      if (!res.rowCount) throw badRequest('This verification link is invalid or has expired');
      await recordAudit(client, req, { userId, action: 'user.email_verified', targetType: 'user', targetId: userId });
    });
    return reply.status(204).send();
  });

  app.post('/refresh', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (req) => {
    const { refreshToken } = parse(refreshRequest, req.body);
    const presented = sha256(refreshToken);
    const result = await withTx(db, async (client): Promise<TokenResponse | null> => {
      const { rows } = await client.query<{ id: string; user_id: string }>(
        `SELECT id, user_id FROM sessions
          WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
          FOR UPDATE`,
        [presented],
      );
      const current = rows[0];
      if (!current) {
        // A previously rotated token being replayed means it was stolen: kill the session.
        const reused = await client.query<{ id: string; user_id: string }>(
          `UPDATE sessions SET revoked_at = now()
            WHERE prev_token_hash = $1 AND revoked_at IS NULL RETURNING id, user_id`,
          [presented],
        );
        const victim = reused.rows[0];
        if (victim) {
          await recordAudit(client, req, {
            userId: victim.user_id,
            action: 'session.refresh_reuse_detected',
            targetType: 'session',
            targetId: victim.id,
          });
        }
        // Return (not throw) so the revocation above is committed, not rolled back.
        return null;
      }
      const next = newRefreshToken();
      await client.query(
        `UPDATE sessions SET prev_token_hash = token_hash, token_hash = $2, last_used_at = now(), ip = $3 WHERE id = $1`,
        [current.id, sha256(next), req.ip],
      );
      return {
        accessToken: await tokens.sign({ sub: current.user_id, sid: current.id }),
        refreshToken: next,
        expiresIn: tokens.ttl,
      };
    });
    if (!result) throw unauthorized('Invalid refresh token');
    return result;
  });

  app.post('/logout', { preHandler: app.authenticate }, async (req, reply) => {
    const { userId, sessionId } = req.auth!;
    await withTx(db, async (client) => {
      await client.query('UPDATE sessions SET revoked_at = now() WHERE id = $1', [sessionId]);
      await recordAudit(client, req, { userId, action: 'user.logout', targetType: 'session', targetId: sessionId });
    });
    return reply.status(204).send();
  });
}
