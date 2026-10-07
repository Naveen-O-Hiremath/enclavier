import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { base32Encode, parseTotp, randomBytes, verifyTotp } from '@enclavier/crypto';
import {
  confirmAuthRequest,
  totpEnableRequest,
  webauthnRegisterFinishRequest,
  type TotpSetupResponse,
  type TwoFactorStatus,
} from '@enclavier/shared';
import { requireAuth } from '../app';
import { recordAudit, type AuditAction } from '../audit';
import { withTx, type Queryable } from '../db';
import { badRequest, notFound, parse, unauthorized } from '../errors';
import { hashRecoveryCode, newRecoveryCodes, verifyAuthSecret } from '../security';
import { notify, relyingParty } from '../twofactor';
import { findUser, type UserRow } from '../users';

const credParam = z.object({ id: z.string().min(1).max(1024) });
const sensitive = { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } };

export async function twoFactorRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;
  app.addHook('preHandler', app.authenticate);

  async function me(req: FastifyRequest): Promise<UserRow> {
    const user = await findUser(db, 'id', requireAuth(req).userId);
    if (!user) throw unauthorized();
    return user;
  }

  /** Destructive 2FA changes require the master password again (not just a session). */
  async function requirePassword(req: FastifyRequest, user: UserRow) {
    const { authHash } = parse(confirmAuthRequest, req.body);
    if (!(await verifyAuthSecret(authHash, user.auth_hash))) throw unauthorized('Master password is incorrect');
  }

  async function replaceRecoveryCodes(client: Queryable, userId: string): Promise<string[]> {
    const codes = newRecoveryCodes();
    await client.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    await client.query('INSERT INTO recovery_codes (user_id, code_hash) SELECT $1, unnest($2::bytea[])', [userId, codes.map(hashRecoveryCode)]);
    return codes;
  }

  /** First factor enabled → issue recovery codes. Last factor removed → drop them. */
  async function afterFactorChange(client: Queryable, userId: string): Promise<string[] | null> {
    const { rows } = await client.query<{ factors: string; codes: string }>(
      `SELECT (SELECT count(*) FROM webauthn_credentials WHERE user_id = $1)
              + (SELECT count(*) FROM users WHERE id = $1 AND totp_enabled_at IS NOT NULL) AS factors,
              (SELECT count(*) FROM recovery_codes WHERE user_id = $1) AS codes`,
      [userId],
    );
    const { factors, codes } = rows[0]!;
    if (Number(factors) === 0) {
      await client.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
      return null;
    }
    return Number(codes) === 0 ? replaceRecoveryCodes(client, userId) : null;
  }

  const audit = (client: Queryable, req: FastifyRequest, userId: string, action: AuditAction, metadata?: Record<string, unknown>) =>
    recordAudit(client, req, { userId, action, targetType: 'user', targetId: userId, metadata });

  app.get('/', async (req): Promise<TwoFactorStatus> => {
    const user = await me(req);
    const [creds, codes] = await Promise.all([
      db.query('SELECT id, name, device_type, backed_up, created_at, last_used_at FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at', [user.id]),
      db.query<{ n: string }>('SELECT count(*) AS n FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL', [user.id]),
    ]);
    return {
      totpEnabled: !!user.totp_enabled_at,
      webauthn: creds.rows.map((c) => ({
        id: c.id,
        name: c.name,
        deviceType: c.device_type,
        backedUp: c.backed_up,
        createdAt: c.created_at.toISOString(),
        lastUsedAt: c.last_used_at?.toISOString() ?? null,
      })),
      recoveryCodesRemaining: Number(codes.rows[0]!.n),
    };
  });

  // ---- authenticator app (TOTP) ----------------------------------------------------

  app.post('/totp/setup', async (req): Promise<TotpSetupResponse> => {
    const user = await me(req);
    const secret = base32Encode(randomBytes(20));
    const label = encodeURIComponent(`Enclavier:${user.email}`);
    const uri = `otpauth://totp/${label}?secret=${secret}&issuer=Enclavier&algorithm=SHA1&digits=6&period=30`;
    // The secret travels in a signed token until the user proves they scanned it.
    const setupToken = await app.purposeTokens.sign('totp-setup', user.id, { secret }, 600);
    return { secret, uri, setupToken };
  });

  app.post('/totp/enable', sensitive, async (req) => {
    const user = await me(req);
    const body = parse(totpEnableRequest, req.body);
    let secret: string;
    try {
      const t = await app.purposeTokens.verify('totp-setup', body.setupToken);
      if (t.sub !== user.id) throw new Error('wrong user');
      secret = String(t.claims.secret);
    } catch {
      throw badRequest('Setup expired. Start again.');
    }
    const counter = verifyTotp(parseTotp(secret), body.code);
    if (counter === null) throw badRequest('That code is not valid. Check the time on your phone and try again.');
    const recoveryCodes = await withTx(db, async (client) => {
      await client.query('UPDATE users SET totp_secret_enc = $2, totp_enabled_at = now(), totp_last_counter = $3 WHERE id = $1', [
        user.id,
        app.secrets.seal(secret),
        counter,
      ]);
      await audit(client, req, user.id, 'user.2fa_totp_enabled');
      return afterFactorChange(client, user.id);
    });
    void notify(app, user.email, 'Authenticator app added to your Enclavier account', [
      'An authenticator app was set up as a second factor for your Enclavier account.',
      "If this wasn't you, change your master password immediately and contact your administrator.",
    ]);
    return { recoveryCodes };
  });

  app.post('/totp/disable', sensitive, async (req, reply) => {
    const user = await me(req);
    await requirePassword(req, user);
    await withTx(db, async (client) => {
      await client.query('UPDATE users SET totp_secret_enc = NULL, totp_enabled_at = NULL, totp_last_counter = NULL WHERE id = $1', [user.id]);
      await audit(client, req, user.id, 'user.2fa_totp_disabled');
      await afterFactorChange(client, user.id);
    });
    void notify(app, user.email, 'Authenticator app removed from your Enclavier account', [
      'The authenticator app was removed from your Enclavier account.',
      "If this wasn't you, change your master password immediately.",
    ]);
    return reply.status(204).send();
  });

  // ---- security keys & passkeys (WebAuthn) -----------------------------------------

  app.post('/webauthn/register/options', async (req) => {
    const user = await me(req);
    const rp = relyingParty(config);
    const { rows } = await db.query<{ id: string; transports: string[] }>('SELECT id, transports FROM webauthn_credentials WHERE user_id = $1', [user.id]);
    const options = await generateRegistrationOptions({
      rpName: rp.rpName,
      rpID: rp.rpID,
      userName: user.email,
      userDisplayName: user.name,
      userID: new TextEncoder().encode(user.id),
      attestationType: 'none',
      excludeCredentials: rows.map((c) => ({ id: c.id, transports: c.transports as AuthenticatorTransportFuture[] })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    });
    const ceremonyToken = await app.purposeTokens.sign('webauthn-register', user.id, { challenge: options.challenge }, 300);
    return { options, ceremonyToken };
  });

  app.post('/webauthn/register/finish', sensitive, async (req) => {
    const user = await me(req);
    const body = parse(webauthnRegisterFinishRequest, req.body);
    let challenge: string;
    try {
      const t = await app.purposeTokens.verify('webauthn-register', body.ceremonyToken);
      if (t.sub !== user.id) throw new Error('wrong user');
      challenge = String(t.claims.challenge);
    } catch {
      throw badRequest('Registration expired. Try again.');
    }
    const rp = relyingParty(config);
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: body.response as unknown as RegistrationResponseJSON,
        expectedChallenge: challenge,
        expectedOrigin: rp.origin,
        expectedRPID: rp.rpID,
        requireUserVerification: false,
      });
    } catch (err) {
      throw badRequest(`Security key registration failed: ${(err as Error).message}`);
    }
    if (!verification.verified || !verification.registrationInfo) throw badRequest('Security key registration failed');
    const info = verification.registrationInfo;
    const recoveryCodes = await withTx(db, async (client) => {
      await client.query(
        `INSERT INTO webauthn_credentials (id, user_id, public_key, counter, transports, name, device_type, backed_up)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          info.credential.id,
          user.id,
          Buffer.from(info.credential.publicKey),
          info.credential.counter,
          info.credential.transports ?? [],
          body.name,
          info.credentialDeviceType,
          info.credentialBackedUp,
        ],
      );
      await audit(client, req, user.id, 'user.2fa_key_added', { name: body.name });
      return afterFactorChange(client, user.id);
    });
    void notify(app, user.email, 'Security key added to your Enclavier account', [
      `A security key or passkey named **${body.name}** was added to your Enclavier account.`,
      "If this wasn't you, change your master password immediately.",
    ]);
    return { recoveryCodes };
  });

  app.post('/webauthn/:id/delete', sensitive, async (req, reply) => {
    const user = await me(req);
    const { id } = parse(credParam, req.params);
    await requirePassword(req, user);
    await withTx(db, async (client) => {
      const res = await client.query('DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2 RETURNING name', [id, user.id]);
      if (!res.rowCount) throw notFound('Security key not found');
      await audit(client, req, user.id, 'user.2fa_key_removed', { name: res.rows[0].name });
      await afterFactorChange(client, user.id);
    });
    return reply.status(204).send();
  });

  // ---- recovery codes ------------------------------------------------------------------

  app.post('/recovery-codes', sensitive, async (req) => {
    const user = await me(req);
    await requirePassword(req, user);
    if (!user.two_factor_enabled) throw badRequest('Enable two-step login first');
    const recoveryCodes = await withTx(db, async (client) => {
      const codes = await replaceRecoveryCodes(client, user.id);
      await audit(client, req, user.id, 'user.2fa_recovery_codes_generated');
      return codes;
    });
    return { recoveryCodes };
  });
}
