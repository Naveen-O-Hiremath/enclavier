import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  combineShares,
  createOrgRecoveryKeyPair,
  decryptItem,
  deriveLoginSecrets,
  encryptCollectionName,
  encryptItem,
  fromB64,
  generateOrgKey,
  openEmergencyUserKey,
  openOrgKey,
  openOrgRecoveryPrivateKey,
  openRecoveredUserKey,
  orgKeyVerifier,
  parseTotp,
  rewrapUserKey,
  sealOrgKey,
  sealUserKeyForEmergency,
  sealUserKeyForRecovery,
  splitSecret,
  toB64,
  totpCode,
  unlockAccount,
  uuid,
} from '@enclavier/crypto';
import type { EmergencyOverview, LoginResult, OrgMember, SyncResponse, TwoFactorChallenge } from '@enclavier/shared';
import type { Db } from '../src/db';
import type { MailMessage } from '../src/mail';
import { DATABASE_URL, FAST_KDF, registerUser, resetDb, setupApp, type TestUser } from './helpers';
import { SoftAuthenticator } from './softAuthenticator';

const ORIGIN = 'https://vault.example.test';
const pw = (email: string) => `${email}-master-password`;

describe.skipIf(!DATABASE_URL)('Phase 3: strong authentication & recovery (integration)', () => {
  let app: FastifyInstance;
  let db: Db;
  let outbox: MailMessage[];

  const sync = async (u: TestUser) => (await app.inject({ method: 'GET', url: '/api/sync', headers: u.auth })).json() as SyncResponse;
  const lastMailTo = (to: string) => [...outbox].reverse().find((m) => m.to === to)!;
  const linkIn = (mail: MailMessage) => new URL(mail.text.match(/https:\/\/\S+/)![0]);

  async function authHashFor(email: string, password = pw(email)) {
    const pre = (await app.inject({ method: 'POST', url: '/api/auth/prelogin', payload: { email } })).json();
    return (await deriveLoginSecrets(password, fromB64(pre.salt), pre.kdf)).authHash;
  }

  async function login(email: string, password = pw(email)): Promise<{ status: number; body: LoginResult }> {
    const res = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email, authHash: await authHashFor(email, password) } });
    return { status: res.statusCode, body: res.json() };
  }

  const secondFactor = (payload: object) => app.inject({ method: 'POST', url: '/api/auth/login/2fa', payload });

  beforeAll(async () => {
    db = await resetDb();
    ({ app, outbox } = await setupApp(db));
  });

  afterAll(async () => {
    await app?.close();
    await db?.end();
  });

  describe('e-mail verification', () => {
    it('verifies the address with the e-mailed link', async () => {
      const u = await registerUser(app, 'verify@acme.test');
      expect((await sync(u)).profile.emailVerified).toBe(false);
      const link = linkIn(lastMailTo('verify@acme.test'));
      expect(link.pathname).toBe('/verify-email');

      const bad = await app.inject({ method: 'POST', url: '/api/auth/verify-email', payload: { userId: u.id, token: 'x'.repeat(43) } });
      expect(bad.statusCode).toBe(400);
      const ok = await app.inject({
        method: 'POST',
        url: '/api/auth/verify-email',
        payload: { userId: link.searchParams.get('user'), token: link.searchParams.get('token') },
      });
      expect(ok.statusCode).toBe(204);
      expect((await sync(u)).profile.emailVerified).toBe(true);
    });
  });

  describe('authenticator app (TOTP)', () => {
    let u: TestUser;
    let secret = '';
    let recoveryCodes: string[] = [];

    it('enables TOTP only after a valid code and issues recovery codes', async () => {
      u = await registerUser(app, 'totp@acme.test');
      const setup = (await app.inject({ method: 'POST', url: '/api/account/2fa/totp/setup', headers: u.auth })).json();
      secret = setup.secret;
      expect(setup.uri).toContain('otpauth://totp/');

      const wrong = await app.inject({ method: 'POST', url: '/api/account/2fa/totp/enable', headers: u.auth, payload: { setupToken: setup.setupToken, code: '000000' } });
      expect(wrong.statusCode).toBe(400);
      // Use the previous time step so the login below (current step) isn't a replay.
      const code = totpCode(parseTotp(secret), Date.now() - 30_000).code;
      const res = await app.inject({ method: 'POST', url: '/api/account/2fa/totp/enable', headers: u.auth, payload: { setupToken: setup.setupToken, code } });
      expect(res.statusCode).toBe(200);
      recoveryCodes = res.json().recoveryCodes;
      expect(recoveryCodes).toHaveLength(10);
      expect((await sync(u)).profile.twoFactorEnabled).toBe(true);
      const { rows } = await db.query('SELECT totp_secret_enc FROM users WHERE id = $1', [u.id]);
      expect(rows[0].totp_secret_enc).not.toContain(secret); // encrypted at rest
    });

    it('withholds tokens and vault keys until the second factor', async () => {
      const step1 = await login(u.email);
      expect(step1.status).toBe(200);
      const challenge = step1.body as TwoFactorChallenge;
      expect(challenge.twoFactorRequired).toBe(true);
      expect(challenge.methods).toEqual(['totp', 'recovery']);
      expect(JSON.stringify(challenge)).not.toContain('protectedUserKey');

      const wrong = await secondFactor({ challengeToken: challenge.challengeToken, method: 'totp', code: '123456' });
      expect(wrong.statusCode).toBe(401);
      const code = totpCode(parseTotp(secret)).code;
      const ok = await secondFactor({ challengeToken: challenge.challengeToken, method: 'totp', code });
      expect(ok.statusCode).toBe(200);
      expect(ok.json().keys.protectedUserKey).toBeTruthy();
      // The same code cannot be replayed.
      const replay = await secondFactor({ challengeToken: challenge.challengeToken, method: 'totp', code });
      expect(replay.statusCode).toBe(401);
    });

    it('accepts each recovery code once', async () => {
      const { body } = await login(u.email);
      const token = (body as TwoFactorChallenge).challengeToken;
      const first = await secondFactor({ challengeToken: token, method: 'recovery', code: recoveryCodes[0]!.toLowerCase() });
      expect(first.statusCode).toBe(200);
      const again = await secondFactor({ challengeToken: token, method: 'recovery', code: recoveryCodes[0] });
      expect(again.statusCode).toBe(401);
      const status = (await app.inject({ method: 'GET', url: '/api/account/2fa', headers: u.auth })).json();
      expect(status.recoveryCodesRemaining).toBe(9);
    });

    it('rejects forged or expired challenge tokens', async () => {
      const res = await secondFactor({ challengeToken: 'e'.repeat(60), method: 'totp', code: '123456' });
      expect(res.statusCode).toBe(401);
    });

    it('requires the master password to disable TOTP', async () => {
      const noPw = await app.inject({ method: 'POST', url: '/api/account/2fa/totp/disable', headers: u.auth, payload: { authHash: 'A'.repeat(43) } });
      expect(noPw.statusCode).toBe(401);
      const ok = await app.inject({ method: 'POST', url: '/api/account/2fa/totp/disable', headers: u.auth, payload: { authHash: await authHashFor(u.email) } });
      expect(ok.statusCode).toBe(204);
      expect(((await login(u.email)).body as { accessToken?: string }).accessToken).toBeTruthy();
    });
  });

  describe('security keys and passkeys (WebAuthn)', () => {
    it('registers a key and signs in with it', async () => {
      const u = await registerUser(app, 'fido@acme.test');
      const key = new SoftAuthenticator(ORIGIN, 'vault.example.test');
      const start = (await app.inject({ method: 'POST', url: '/api/account/2fa/webauthn/register/options', headers: u.auth })).json();
      const finish = await app.inject({
        method: 'POST',
        url: '/api/account/2fa/webauthn/register/finish',
        headers: u.auth,
        payload: { ceremonyToken: start.ceremonyToken, name: 'YubiKey 5', response: key.register(start.options) },
      });
      expect(finish.statusCode).toBe(200);
      expect(finish.json().recoveryCodes).toHaveLength(10);

      const { body } = await login(u.email);
      const challenge = body as TwoFactorChallenge;
      expect(challenge.methods).toContain('webauthn');
      const options = challenge.webauthnOptions as { challenge: string };

      // An assertion for a different challenge (e.g. phished from another session) fails.
      const stale = await secondFactor({ challengeToken: challenge.challengeToken, method: 'webauthn', webauthnResponse: key.authenticate({ challenge: 'bm9wZQ' }) });
      expect(stale.statusCode).toBe(401);

      const ok = await secondFactor({ challengeToken: challenge.challengeToken, method: 'webauthn', webauthnResponse: key.authenticate(options) });
      expect(ok.statusCode).toBe(200);
      const status = (await app.inject({ method: 'GET', url: '/api/account/2fa', headers: u.auth })).json();
      expect(status.webauthn[0]).toMatchObject({ name: 'YubiKey 5' });
      expect(status.webauthn[0].lastUsedAt).toBeTruthy();
    });

    it('rejects a key registered for another origin', async () => {
      const u = await registerUser(app, 'phish@acme.test');
      const key = new SoftAuthenticator('https://evil.example', 'vault.example.test');
      const start = (await app.inject({ method: 'POST', url: '/api/account/2fa/webauthn/register/options', headers: u.auth })).json();
      const res = await app.inject({
        method: 'POST',
        url: '/api/account/2fa/webauthn/register/finish',
        headers: u.auth,
        payload: { ceremonyToken: start.ceremonyToken, name: 'Evil', response: key.register(start.options) },
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('organization policies & recovery', () => {
    let owner: TestUser;
    let member: TestUser;
    const orgId = uuid();
    const collectionId = uuid();
    const orgKey = generateOrgKey();
    let memberRow: OrgMember;

    beforeAll(async () => {
      owner = await registerUser(app, 'owner@corp.test');
      member = await registerUser(app, 'member@corp.test');
      await app.inject({
        method: 'POST',
        url: '/api/orgs',
        headers: owner.auth,
        payload: {
          id: orgId,
          name: 'Corp',
          protectedOrgKey: sealOrgKey(toB64(owner.keys.publicKey), orgKey, orgId),
          defaultCollection: { id: collectionId, name: encryptCollectionName(orgKey, collectionId, 'Default') },
        },
      });
      await app.inject({
        method: 'POST',
        url: `/api/orgs/${orgId}/members/invite`,
        headers: owner.auth,
        payload: { emails: [member.email], role: 'member', collections: [{ id: collectionId, permission: 'view' }] },
      });
      const link = linkIn(outbox.find((m) => m.to === member.email && m.subject.includes('invited you'))!);
      await app.inject({
        method: 'POST',
        url: '/api/invites/accept',
        headers: member.auth,
        payload: { orgId, memberId: link.searchParams.get('member'), token: link.searchParams.get('token') },
      });
      memberRow = (await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/members`, headers: owner.auth })).json().find((m: OrgMember) => m.email === member.email);
      await app.inject({
        method: 'POST',
        url: `/api/orgs/${orgId}/members/${memberRow.id}/confirm`,
        headers: owner.auth,
        payload: { protectedOrgKey: sealOrgKey(memberRow.publicKey!, orgKey, orgId) },
      });
    });

    async function enableTotp(u: TestUser) {
      const setup = (await app.inject({ method: 'POST', url: '/api/account/2fa/totp/setup', headers: u.auth })).json();
      const code = totpCode(parseTotp(setup.secret)).code;
      await app.inject({ method: 'POST', url: '/api/account/2fa/totp/enable', headers: u.auth, payload: { setupToken: setup.setupToken, code } });
    }

    it('require-2FA policy blocks non-compliant members until they enroll', async () => {
      const put = (enabled: boolean) =>
        app.inject({ method: 'PUT', url: `/api/orgs/${orgId}/policies`, headers: owner.auth, payload: { type: 'require_2fa', enabled } });
      expect((await put(true)).statusCode).toBe(400); // the admin must have 2FA first
      await enableTotp(owner);
      expect((await put(true)).statusCode).toBe(200);

      const blocked = await sync(member);
      expect(blocked.organizations[0]).toMatchObject({ blockedByPolicy: 'require_2fa', protectedOrgKey: null });
      expect(blocked.collections).toHaveLength(0);
      expect((await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/collections`, headers: member.auth })).statusCode).toBe(403);

      await enableTotp(member);
      const ok = await sync(member);
      expect(ok.organizations[0]!.blockedByPolicy).toBeNull();
      expect(ok.collections).toHaveLength(1);
      await put(false);
    });

    it('lets an admin reset an enrolled member’s master password', async () => {
      // Owner enables account recovery (creating the org recovery key pair in the browser).
      const pair = createOrgRecoveryKeyPair(orgKey, orgId);
      const enable = await app.inject({
        method: 'PUT',
        url: `/api/orgs/${orgId}/policies`,
        headers: owner.auth,
        payload: { type: 'account_recovery', enabled: true, autoEnroll: false, recoveryKeyPair: pair },
      });
      expect(enable.statusCode).toBe(200);

      // Member has a personal item and enrolls.
      const itemId = uuid();
      await app.inject({ method: 'POST', url: '/api/items', headers: member.auth, payload: encryptItem(member.keys.userKey, itemId, null, { type: 'note', name: 'diary' }) });
      const s = await sync(member);
      expect(s.organizations[0]!.recoveryPublicKey).toBe(pair.publicKey);
      const notEnrolled = await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/members/${memberRow.id}/recovery`, headers: owner.auth });
      expect(notEnrolled.statusCode).toBe(400);
      await app.inject({
        method: 'POST',
        url: `/api/orgs/${orgId}/recovery/enroll`,
        headers: member.auth,
        payload: { recoveryKey: sealUserKeyForRecovery(s.organizations[0]!.recoveryPublicKey!, member.keys.userKey, orgId, member.id) },
      });

      // Admin side: recover the user key and wrap it under a temporary password.
      const material = (await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/members/${memberRow.id}/recovery`, headers: owner.auth })).json();
      const recoveryPrivate = openOrgRecoveryPrivateKey(orgKey, orgId, material.protectedRecoveryPrivateKey);
      const userKey = openRecoveredUserKey(recoveryPrivate, material.recoveryKey, orgId, material.userId);
      const reset = await rewrapUserKey({ userKey }, 'Temporary-Pass-2026!', FAST_KDF);
      const res = await app.inject({ method: 'POST', url: `/api/orgs/${orgId}/members/${memberRow.id}/recover`, headers: owner.auth, payload: reset });
      expect(res.statusCode).toBe(204);

      // Old sessions are dead, the old password is gone, the temporary one works and must be changed.
      expect((await app.inject({ method: 'GET', url: '/api/sync', headers: member.auth })).statusCode).toBe(401);
      expect((await login(member.email)).status).toBe(401);
      const step1 = (await login(member.email, 'Temporary-Pass-2026!')).body as TwoFactorChallenge;
      const code = totpCode(parseTotp(app.secrets.open((await db.query('SELECT totp_secret_enc FROM users WHERE id = $1', [member.id])).rows[0].totp_secret_enc)), Date.now() + 30_000).code;
      const done = await secondFactor({ challengeToken: step1.challengeToken, method: 'totp', code });
      expect(done.statusCode).toBe(200);
      expect(done.json().profile.forcePasswordChange).toBe(true);
      const keys = await unlockAccount('Temporary-Pass-2026!', done.json().keys);
      member.auth = { authorization: `Bearer ${done.json().accessToken}` };
      const item = (await sync(member)).items.find((i) => i.id === itemId)!;
      expect(decryptItem<{ name: string }>(keys.userKey, item).name).toBe('diary');
      expect(lastMailTo(member.email).subject).toContain('reset by an administrator');

      // Members can't recover others; admins can't recover themselves.
      const self = await app.inject({ method: 'GET', url: `/api/orgs/${orgId}/members/${memberRow.id}/recovery`, headers: member.auth });
      expect(self.statusCode).toBe(403);
    });

    it('break-glass: enough recovery shares make the holder an owner', async () => {
      const shares = splitSecret(orgKey, 5, 3);
      const kit = await app.inject({
        method: 'POST',
        url: `/api/orgs/${orgId}/recovery-kit`,
        headers: owner.auth,
        payload: { verifier: orgKeyVerifier(orgKey, orgId), shares: 5, threshold: 3 },
      });
      expect(kit.statusCode).toBe(204);

      const officer = await registerUser(app, 'officer@corp.test');
      const tooFew = combineShares([shares[0]!, shares[1]!]);
      const denied = await app.inject({
        method: 'POST',
        url: '/api/orgs/break-glass',
        headers: officer.auth,
        payload: { orgId, verifier: orgKeyVerifier(tooFew, orgId), protectedOrgKey: sealOrgKey(toB64(officer.keys.publicKey), tooFew, orgId) },
      });
      expect(denied.statusCode).toBe(403);

      const recovered = combineShares([shares[4]!, shares[1]!, shares[2]!]);
      const res = await app.inject({
        method: 'POST',
        url: '/api/orgs/break-glass',
        headers: officer.auth,
        payload: { orgId, verifier: orgKeyVerifier(recovered, orgId), protectedOrgKey: sealOrgKey(toB64(officer.keys.publicKey), recovered, orgId) },
      });
      expect(res.statusCode).toBe(200);
      const s = await sync(officer);
      expect(s.organizations[0]).toMatchObject({ role: 'owner', status: 'confirmed' });
      expect(openOrgKey(officer.keys.privateKey, s.organizations[0]!.protectedOrgKey!, orgId)).toEqual(orgKey);
      expect(lastMailTo(owner.email).subject).toContain('Break-glass');
    });
  });

  describe('emergency access', () => {
    it('grants read-only vault access after the waiting period unless rejected', async () => {
      const grantor = await registerUser(app, 'grantor@home.test');
      const grantee = await registerUser(app, 'grantee@home.test');
      const itemId = uuid();
      await app.inject({ method: 'POST', url: '/api/items', headers: grantor.auth, payload: encryptItem(grantor.keys.userKey, itemId, null, { type: 'note', name: 'will' }) });

      const inv = await app.inject({ method: 'POST', url: '/api/emergency/invite', headers: grantor.auth, payload: { email: grantee.email, waitDays: 2 } });
      expect(inv.statusCode).toBe(201);
      const link = linkIn(lastMailTo(grantee.email));
      const id = link.searchParams.get('id')!;
      expect((await app.inject({ method: 'POST', url: '/api/emergency/accept', headers: grantor.auth, payload: { id, token: link.searchParams.get('token') } })).statusCode).toBe(403);
      expect((await app.inject({ method: 'POST', url: '/api/emergency/accept', headers: grantee.auth, payload: { id, token: link.searchParams.get('token') } })).statusCode).toBe(204);

      const overview = (await app.inject({ method: 'GET', url: '/api/emergency', headers: grantor.auth })).json() as EmergencyOverview;
      const grant = overview.granted[0]!;
      expect(grant.status).toBe('accepted');
      await app.inject({
        method: 'POST',
        url: `/api/emergency/${id}/confirm`,
        headers: grantor.auth,
        payload: { keySealed: sealUserKeyForEmergency(grant.publicKey!, grantor.keys.userKey, id) },
      });

      const vault = () => app.inject({ method: 'GET', url: `/api/emergency/${id}/vault`, headers: grantee.auth });
      expect((await vault()).statusCode).toBe(403);
      await app.inject({ method: 'POST', url: `/api/emergency/${id}/initiate`, headers: grantee.auth });
      expect(lastMailTo(grantor.email).subject).toContain('requested emergency access');
      expect((await vault()).statusCode).toBe(403); // still waiting

      // Grantor rejects; grantee asks again; the waiting period elapses.
      await app.inject({ method: 'POST', url: `/api/emergency/${id}/reject`, headers: grantor.auth });
      expect((await app.inject({ method: 'GET', url: '/api/emergency', headers: grantee.auth })).json().trustedBy[0].status).toBe('confirmed');
      await app.inject({ method: 'POST', url: `/api/emergency/${id}/initiate`, headers: grantee.auth });
      await db.query(`UPDATE emergency_access SET recovery_initiated_at = now() - interval '3 days' WHERE id = $1`, [id]);

      const res = await vault();
      expect(res.statusCode).toBe(200);
      const body = res.json();
      const userKey = openEmergencyUserKey(grantee.keys.privateKey, body.keySealed, id);
      expect(decryptItem<{ name: string }>(userKey, body.items[0]).name).toBe('will');

      // Only the grantee can read it.
      const other = await registerUser(app, 'other@home.test');
      expect((await app.inject({ method: 'GET', url: `/api/emergency/${id}/vault`, headers: other.auth })).statusCode).toBe(404);
    });
  });
});
