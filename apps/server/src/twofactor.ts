import type { FastifyInstance } from 'fastify';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
} from '@simplewebauthn/server';
import { parseTotp, verifyTotp } from '@enclavier/crypto';
import type { TwoFactorChallenge, TwoFactorMethod } from '@enclavier/shared';
import type { Config } from './config';
import type { Queryable } from './db';
import { noticeEmail } from './mail';
import { hashRecoveryCode, newRefreshToken, sha256 } from './security';
import type { UserRow } from './users';

export const MFA_CHALLENGE_TTL = 300;
export const EMAIL_VERIFY_TTL_HOURS = 48;

export function relyingParty(config: Config) {
  const url = new URL(config.PUBLIC_URL);
  return { rpID: config.WEBAUTHN_RP_ID || url.hostname, rpName: config.WEBAUTHN_RP_NAME, origin: url.origin };
}

interface CredentialRow {
  id: string;
  public_key: Buffer;
  counter: string;
  transports: string[];
}

async function credentials(client: Queryable, userId: string): Promise<CredentialRow[]> {
  const { rows } = await client.query<CredentialRow>('SELECT id, public_key, counter, transports FROM webauthn_credentials WHERE user_id = $1', [userId]);
  return rows;
}

/** Context carried through the second-factor step (all optional, SSO fills the last three). */
export interface ChallengeContext {
  deviceName?: string;
  deviceId?: string;
  replacesSessionId?: string;
  orgId?: string;
}

/** Builds the second-factor challenge returned by /auth/login, or null when the user has no 2FA. */
export async function createLoginChallenge(app: FastifyInstance, user: UserRow, ctx: ChallengeContext = {}): Promise<TwoFactorChallenge | null> {
  if (!user.two_factor_enabled) return null;
  const creds = await credentials(app.db, user.id);
  const methods: TwoFactorMethod[] = [];
  let webauthnOptions: Awaited<ReturnType<typeof generateAuthenticationOptions>> | null = null;
  if (creds.length) {
    methods.push('webauthn');
    webauthnOptions = await generateAuthenticationOptions({
      rpID: relyingParty(app.config).rpID,
      allowCredentials: creds.map((c) => ({ id: c.id, transports: c.transports as AuthenticatorTransportFuture[] })),
      userVerification: 'preferred',
    });
  }
  if (user.totp_enabled_at) methods.push('totp');
  methods.push('recovery');
  const challengeToken = await app.purposeTokens.sign(
    'mfa',
    user.id,
    {
      webauthnChallenge: webauthnOptions?.challenge ?? '',
      deviceName: ctx.deviceName ?? '',
      deviceId: ctx.deviceId ?? '',
      replacesSessionId: ctx.replacesSessionId ?? '',
      orgId: ctx.orgId ?? '',
    },
    MFA_CHALLENGE_TTL,
  );
  return { twoFactorRequired: true, challengeToken, methods, webauthnOptions };
}

/** Verifies one second factor. Single-use factors (TOTP steps, recovery codes) are consumed. */
export async function verifySecondFactor(
  app: FastifyInstance,
  client: Queryable,
  user: UserRow,
  input: { method: TwoFactorMethod; code?: string; webauthnResponse?: Record<string, unknown>; webauthnChallenge?: string },
): Promise<boolean> {
  if (input.method === 'totp') {
    if (!user.totp_secret_enc || !user.totp_enabled_at || !input.code) return false;
    const counter = verifyTotp(parseTotp(app.secrets.open(user.totp_secret_enc)), input.code);
    if (counter === null) return false;
    // Each time step is accepted once: a shoulder-surfed or phished code can't be replayed.
    const res = await client.query(
      'UPDATE users SET totp_last_counter = $2 WHERE id = $1 AND (totp_last_counter IS NULL OR totp_last_counter < $2)',
      [user.id, counter],
    );
    return res.rowCount === 1;
  }

  if (input.method === 'recovery') {
    if (!input.code) return false;
    const res = await client.query('UPDATE recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL', [
      user.id,
      hashRecoveryCode(input.code),
    ]);
    return res.rowCount === 1;
  }

  // WebAuthn (security key / passkey)
  const response = input.webauthnResponse as unknown as AuthenticationResponseJSON | undefined;
  if (!response?.id || !input.webauthnChallenge) return false;
  const { rows } = await client.query<CredentialRow>(
    'SELECT id, public_key, counter, transports FROM webauthn_credentials WHERE user_id = $1 AND id = $2',
    [user.id, response.id],
  );
  const cred = rows[0];
  if (!cred) return false;
  const rp = relyingParty(app.config);
  try {
    const result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: input.webauthnChallenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpID,
      credential: {
        id: cred.id,
        publicKey: new Uint8Array(cred.public_key),
        counter: Number(cred.counter),
        transports: cred.transports as AuthenticatorTransportFuture[],
      },
      requireUserVerification: false,
    });
    if (!result.verified) return false;
    await client.query('UPDATE webauthn_credentials SET counter = $2, last_used_at = now() WHERE id = $1', [
      cred.id,
      result.authenticationInfo.newCounter,
    ]);
    return true;
  } catch (err) {
    app.log.warn({ err }, 'WebAuthn assertion rejected');
    return false;
  }
}

// ---- e-mail verification -----------------------------------------------------------

/** Stores a fresh verification token; send the returned link after the transaction commits. */
export async function issueEmailVerification(client: Queryable, config: Config, userId: string): Promise<string> {
  const token = newRefreshToken();
  await client.query(
    `UPDATE users SET email_verify_token_hash = $2, email_verify_expires_at = now() + make_interval(hours => $3) WHERE id = $1`,
    [userId, sha256(token), EMAIL_VERIFY_TTL_HOURS],
  );
  return `${config.PUBLIC_URL.replace(/\/$/, '')}/verify-email?user=${userId}&token=${token}`;
}

export async function sendVerificationEmail(app: FastifyInstance, to: string, name: string, link: string): Promise<void> {
  try {
    await app.mailer.send({
      to,
      ...noticeEmail({
        subject: 'Verify your e-mail address for Enclavier',
        heading: 'Confirm your e-mail address',
        preheader: 'One click to finish setting up your Enclavier account.',
        paragraphs: [`Hi ${name}, please confirm that **${to}** belongs to you. This lets your organization invite you and lets us send you security alerts.`],
        cta: { label: 'Verify e-mail', url: link },
        footnote: `This link expires in ${EMAIL_VERIFY_TTL_HOURS} hours. If you didn't create an Enclavier account, ignore this e-mail.`,
      }),
    });
  } catch (err) {
    app.log.error({ err, to }, 'Failed to send verification e-mail');
  }
}

/** Fire-and-forget security notification (never blocks or fails the request). */
export async function notify(app: FastifyInstance, to: string, subject: string, paragraphs: string[], cta?: { label: string; url: string }) {
  try {
    await app.mailer.send({
      to,
      ...noticeEmail({
        subject,
        tone: 'security',
        paragraphs,
        cta,
        footnote: "You're receiving this security notice because it concerns your Enclavier account.",
      }),
    });
  } catch (err) {
    app.log.error({ err, to, subject }, 'Failed to send notification e-mail');
  }
}
