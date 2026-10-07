import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { SignedXml } from 'xml-crypto';
import {
  createAccount,
  deriveLoginSecrets,
  fromB64,
  encryptCollectionName,
  generateOrgKey,
  generateKeyPair as generateX25519,
  openDeviceUserKey,
  sealOrgKey,
  sealUserKeyForDevice,
  toB64,
  uuid,
} from '@enclavier/crypto';
import type { LoginResponse, OrgMember, SsoExchangeResult } from '@enclavier/shared';
import type { Db } from '../src/db';
import type { MailMessage } from '../src/mail';
import { DATABASE_URL, FAST_KDF, registerUser, resetDb, setupApp, type TestUser } from './helpers';

const CLIENT_ID = 'enclavier-test-client';
const CLIENT_SECRET = 'idp-client-secret-value';

/** A minimal OpenID provider: discovery, JWKS and a PKCE-checking token endpoint. */
async function startIdp() {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  const codes = new Map<string, { challenge: string; nonce: string; claims: Record<string, unknown> }>();
  let issuer = '';
  const server: Server = createServer((req, res) => {
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (req.url === '/.well-known/openid-configuration') {
      return json(200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        code_challenge_methods_supported: ['S256'],
      });
    }
    if (req.url === '/jwks') return json(200, { keys: [jwk] });
    if (req.url === '/token' && req.method === 'POST') {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', async () => {
        const body = new URLSearchParams(raw);
        const basic = req.headers.authorization?.startsWith('Basic ')
          ? Buffer.from(req.headers.authorization.slice(6), 'base64').toString().split(':').map(decodeURIComponent)
          : null;
        const secret = basic ? basic[1] : body.get('client_secret');
        if (secret !== CLIENT_SECRET) return json(401, { error: 'invalid_client' });
        const grant = codes.get(body.get('code') ?? '');
        codes.delete(body.get('code') ?? '');
        const verifier = body.get('code_verifier') ?? '';
        if (!grant || createHash('sha256').update(verifier).digest('base64url') !== grant.challenge) return json(400, { error: 'invalid_grant' });
        const idToken = await new SignJWT({ nonce: grant.nonce, ...grant.claims })
          .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
          .setIssuer(issuer)
          .setAudience(CLIENT_ID)
          .setSubject(String(grant.claims.sub))
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(privateKey);
        json(200, { access_token: 'at', token_type: 'Bearer', expires_in: 300, id_token: idToken });
      });
      return;
    }
    json(404, {});
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  /** Plays the user signing in at the IdP: returns the callback query. */
  const authorize = (redirectUrl: string, claims: Record<string, unknown>) => {
    const u = new URL(redirectUrl);
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    const code = randomBytes(16).toString('hex');
    codes.set(code, { challenge: u.searchParams.get('code_challenge')!, nonce: u.searchParams.get('nonce')!, claims });
    return { code, state: u.searchParams.get('state')! };
  };
  return { server, issuer: () => issuer, authorize };
}

// ---- SAML test IdP (fixture certificate, test only) -----------------------------------------

const SAML_KEY = readFileSync(new URL('./fixtures/saml-idp.key', import.meta.url), 'utf8');
const SAML_CERT = readFileSync(new URL('./fixtures/saml-idp.crt', import.meta.url), 'utf8');
const IDP_ENTITY = 'https://idp.example.test/saml';

function samlResponse(o: { acs: string; audience: string; inResponseTo: string; email: string; groups?: string[]; tamper?: boolean }) {
  const now = new Date();
  const later = new Date(now.getTime() + 5 * 60_000).toISOString();
  const attrs = (o.groups ?? []).map((g) => `<saml:AttributeValue>${g}</saml:AttributeValue>`).join('');
  const xml =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${uuid().replace(/-/g, '')}" Version="2.0" IssueInstant="${now.toISOString()}" Destination="${o.acs}" InResponseTo="${o.inResponseTo}">` +
    `<saml:Issuer>${IDP_ENTITY}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    `<saml:Assertion ID="_a${uuid().replace(/-/g, '')}" Version="2.0" IssueInstant="${now.toISOString()}">` +
    `<saml:Issuer>${IDP_ENTITY}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${o.email}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${o.inResponseTo}" NotOnOrAfter="${later}" Recipient="${o.acs}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${new Date(now.getTime() - 60_000).toISOString()}" NotOnOrAfter="${later}"><saml:AudienceRestriction><saml:Audience>${o.audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `<saml:AttributeStatement><saml:Attribute Name="groups">${attrs}</saml:Attribute></saml:AttributeStatement>` +
    `</saml:Assertion></samlp:Response>`;
  const sig = new SignedXml({
    privateKey: SAML_KEY,
    publicCert: SAML_CERT,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  sig.computeSignature(xml, { location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' } });
  let signed = sig.getSignedXml();
  if (o.tamper) signed = signed.replace(`>${o.email}<`, '>ceo@acme.test<');
  return Buffer.from(signed).toString('base64');
}

const binding = () => {
  const secret = randomBytes(32).toString('base64url');
  return { secret, hash: createHash('sha256').update(secret).digest('base64url') };
};

describe.skipIf(!DATABASE_URL)('Enterprise identity: SSO, trusted devices, SCIM (integration)', () => {
  let app: FastifyInstance;
  let db: Db;
  let outbox: MailMessage[];
  let idp: Awaited<ReturnType<typeof startIdp>>;
  let alice: TestUser; // owner of Acme (OIDC)
  let bob: TestUser; // owner of Globex (SAML)
  let carol: TestUser; // personal account on an unverified domain
  const txt = new Map<string, string[][]>();
  const acme = uuid();
  const globex = uuid();
  const acmeKey = generateOrgKey();

  let newbie: { id: string; login: LoginResponse; password: ReturnType<typeof createAccount> extends Promise<infer T> ? T : never };

  async function createOrg(owner: TestUser, id: string, name: string, key = generateOrgKey()) {
    const col = uuid();
    const res = await app.inject({
      method: 'POST',
      url: '/api/orgs',
      headers: owner.auth,
      payload: {
        id,
        name,
        protectedOrgKey: sealOrgKey(toB64(owner.keys.publicKey), key, id),
        defaultCollection: { id: col, name: encryptCollectionName(key, col, 'Default') },
      },
    });
    expect(res.statusCode).toBe(201);
  }

  const oidcConfig = (over: Record<string, unknown> = {}) => ({
    enabled: true,
    identifier: 'acme',
    jitProvisioning: true,
    enforce: false,
    groupSync: true,
    settings: { type: 'oidc', issuer: idp.issuer(), clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, groupsClaim: 'groups' },
    ...over,
  });

  /** Browser → /sso/start → IdP → callback → web vault fragment → /sso/exchange. */
  async function oidcSignIn(claims: Record<string, unknown>, extra: Record<string, unknown> = {}, wrongBinding = false) {
    const b = binding();
    const start = await app.inject({ method: 'POST', url: '/api/sso/start', payload: { identifier: 'acme', binding: b.hash } });
    expect(start.statusCode).toBe(200);
    const { code, state } = idp.authorize(start.json().redirectUrl, claims);
    const cb = await app.inject({ method: 'GET', url: `/api/sso/oidc/callback?code=${code}&state=${state}` });
    expect(cb.statusCode).toBe(303);
    const fragment = new URLSearchParams(new URL(cb.headers.location as string).hash.slice(1));
    if (fragment.get('error')) return { error: fragment.get('error')!, status: 0, body: null as unknown as SsoExchangeResult, code: '' };
    const exchangeCode = fragment.get('code')!;
    const res = await app.inject({
      method: 'POST',
      url: '/api/sso/exchange',
      payload: { code: exchangeCode, bindingSecret: wrongBinding ? binding().secret : b.secret, ...extra },
    });
    return { status: res.statusCode, body: res.json() as SsoExchangeResult, code: exchangeCode, secret: b.secret, error: null };
  }

  beforeAll(async () => {
    idp = await startIdp();
    db = await resetDb();
    ({ app, outbox } = await setupApp(db, { ALLOW_PRIVATE_SSO_ENDPOINTS: 'true' }, { resolveTxt: async (name) => txt.get(name) ?? [] }));
    alice = await registerUser(app, 'alice@acme.test');
    bob = await registerUser(app, 'bob@globex.test');
    carol = await registerUser(app, 'carol@gmail.test');
    await createOrg(alice, acme, 'Acme', acmeKey);
    await createOrg(bob, globex, 'Globex');
  });

  afterAll(async () => {
    await app?.close();
    await db?.end();
    idp?.server.close();
  });

  // ---- configuration ---------------------------------------------------------------------

  it('verifies domain ownership with a DNS TXT record, once per domain', async () => {
    const add = await app.inject({ method: 'POST', url: `/api/orgs/${acme}/domains`, headers: alice.auth, payload: { domain: 'acme.test' } });
    expect(add.statusCode).toBe(201);
    const domain = add.json();
    expect(domain.record.name).toBe('_enclavier.acme.test');

    const early = await app.inject({ method: 'POST', url: `/api/orgs/${acme}/domains/${domain.id}/verify`, headers: alice.auth });
    expect(early.json()).toMatchObject({ verified: false });

    txt.set('_enclavier.acme.test', [[domain.record.value.slice(0, 20), domain.record.value.slice(20)]]); // chunked TXT
    const ok = await app.inject({ method: 'POST', url: `/api/orgs/${acme}/domains/${domain.id}/verify`, headers: alice.auth });
    expect(ok.json()).toMatchObject({ verified: true });

    // Another tenant can add the name but can't claim it once verified elsewhere.
    const theirs = (await app.inject({ method: 'POST', url: `/api/orgs/${globex}/domains`, headers: bob.auth, payload: { domain: 'acme.test' } })).json();
    txt.set('_enclavier.acme.test', [[theirs.record.value]]);
    const stolen = await app.inject({ method: 'POST', url: `/api/orgs/${globex}/domains/${theirs.id}/verify`, headers: bob.auth });
    expect(stolen.statusCode).toBe(409);
  });

  it('stores OIDC settings encrypted, masks the client secret and keeps it on re-save', async () => {
    const put = await app.inject({ method: 'PUT', url: `/api/orgs/${acme}/sso`, headers: alice.auth, payload: oidcConfig() });
    expect(put.statusCode).toBe(200);
    const view = (await app.inject({ method: 'GET', url: `/api/orgs/${acme}/sso`, headers: alice.auth })).json();
    expect(view.config.settings.clientSecret).toBe(`••••${CLIENT_SECRET.slice(-4)}`);
    expect(view.serviceProvider.redirectUri).toBe('https://vault.example.test/api/sso/oidc/callback');
    const raw = await db.query('SELECT settings_enc FROM sso_configs WHERE org_id = $1', [acme]);
    expect(raw.rows[0].settings_enc).not.toContain(CLIENT_SECRET);

    const again = oidcConfig();
    (again.settings as Record<string, unknown>).clientSecret = view.config.settings.clientSecret;
    expect((await app.inject({ method: 'PUT', url: `/api/orgs/${acme}/sso`, headers: alice.auth, payload: again })).statusCode).toBe(200);

    // Identifiers are unique across tenants.
    const clash = await app.inject({
      method: 'PUT',
      url: `/api/orgs/${globex}/sso`,
      headers: bob.auth,
      payload: { ...oidcConfig(), enabled: false },
    });
    expect(clash.statusCode).toBe(409);

    const discover = await app.inject({ method: 'POST', url: '/api/sso/discover', payload: { email: 'someone@acme.test' } });
    expect(discover.json()).toEqual({ available: true, orgName: 'Acme', identifier: 'acme' });
    expect((await app.inject({ method: 'POST', url: '/api/sso/discover', payload: { email: 'x@nowhere.test' } })).json()).toEqual({ available: false });
  });

  it('refuses identity providers on private networks unless the operator allows it', async () => {
    const { app: saas } = await setupApp(db);
    try {
      const res = await saas.inject({ method: 'PUT', url: `/api/orgs/${acme}/sso`, headers: alice.auth, payload: oidcConfig() });
      expect(res.statusCode).toBe(400);
      expect(res.json().message).toMatch(/https/i);
      const internal = oidcConfig();
      (internal.settings as Record<string, unknown>).issuer = 'https://169.254.169.254/';
      const metadata = await saas.inject({ method: 'PUT', url: `/api/orgs/${acme}/sso`, headers: alice.auth, payload: internal });
      expect(metadata.statusCode).toBe(400);
      expect(metadata.json().message).toMatch(/private or internal address/);
    } finally {
      await saas.close();
    }
  });

  // ---- OIDC sign-in ------------------------------------------------------------------------

  it('provisions a new account just in time for a verified domain and syncs IdP groups', async () => {
    const group = await app.inject({
      method: 'POST',
      url: `/api/orgs/${acme}/groups`,
      headers: alice.auth,
      payload: { name: 'Engineering', collections: [], memberIds: [], externalId: 'eng' },
    });
    expect(group.statusCode).toBe(201);

    const r = await oidcSignIn({ sub: 'idp-user-1', email: 'dana@acme.test', email_verified: true, name: 'Dana Scully', groups: ['eng', 'unmapped'] });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ status: 'provision', email: 'dana@acme.test', name: 'Dana Scully', orgName: 'Acme' });
    if (r.body.status !== 'provision') throw new Error('unreachable');

    const password = await createAccount('dana-very-long-master-password', FAST_KDF);
    const prov = await app.inject({
      method: 'POST',
      url: '/api/sso/provision',
      payload: { ...password.payload, name: 'Dana Scully', provisionToken: r.body.provisionToken },
    });
    expect(prov.statusCode).toBe(201);
    const login = prov.json() as LoginResponse;
    expect(login.profile).toMatchObject({ email: 'dana@acme.test', emailVerified: true });
    newbie = { id: login.profile.id, login, password };

    const members = (await app.inject({ method: 'GET', url: `/api/orgs/${acme}/members`, headers: alice.auth })).json() as OrgMember[];
    const dana = members.find((m) => m.email === 'dana@acme.test')!;
    expect(dana).toMatchObject({ status: 'accepted', ssoLinked: true, groups: [group.json().id] });

    // A second provisioning attempt with the same token can't create a second account.
    const again = await app.inject({ method: 'POST', url: '/api/sso/provision', payload: { ...password.payload, name: 'x', provisionToken: r.body.provisionToken } });
    expect(again.statusCode).toBe(409);
  });

  it('signs a linked user in, and exchange codes are single-use and bound to the starting browser', async () => {
    const r = await oidcSignIn({ sub: 'idp-user-1', email: 'dana@acme.test', groups: [] });
    expect(r.body.status).toBe('authenticated');
    // Group sync removed Dana from the IdP-managed group she no longer has.
    const members = (await app.inject({ method: 'GET', url: `/api/orgs/${acme}/members`, headers: alice.auth })).json() as OrgMember[];
    expect(members.find((m) => m.email === 'dana@acme.test')!.groups).toEqual([]);

    const replay = await app.inject({ method: 'POST', url: '/api/sso/exchange', payload: { code: r.code, bindingSecret: r.secret } });
    expect(replay.statusCode).toBe(401);

    const csrf = await oidcSignIn({ sub: 'idp-user-1', email: 'dana@acme.test' }, {}, true);
    expect(csrf.status).toBe(401);
  });

  it('never auto-links an existing account on a domain the organization does not own', async () => {
    await app.inject({ method: 'POST', url: `/api/orgs/${acme}/members/invite`, headers: alice.auth, payload: { emails: ['carol@gmail.test'], role: 'member' } });
    const r = await oidcSignIn({ sub: 'idp-carol', email: 'carol@gmail.test' });
    expect(r.body.status).toBe('link_required');
    if (r.body.status !== 'link_required') throw new Error('unreachable');

    // Only the account owner (signed in with their master password) can complete the link.
    const wrong = await app.inject({ method: 'POST', url: '/api/sso/link', headers: alice.auth, payload: { linkToken: r.body.linkToken } });
    expect(wrong.statusCode).toBe(403);
    const link = await app.inject({ method: 'POST', url: '/api/sso/link', headers: carol.auth, payload: { linkToken: r.body.linkToken } });
    expect(link.statusCode).toBe(204);

    const members = (await app.inject({ method: 'GET', url: `/api/orgs/${acme}/members`, headers: alice.auth })).json() as OrgMember[];
    expect(members.find((m) => m.email === 'carol@gmail.test')).toMatchObject({ status: 'accepted', ssoLinked: true });
    expect((await oidcSignIn({ sub: 'idp-carol', email: 'carol@gmail.test' })).body.status).toBe('authenticated');
  });

  it('rejects unknown users without an invitation and unverified IdP e-mails', async () => {
    const stranger = await oidcSignIn({ sub: 'idp-x', email: 'eve@gmail.test' });
    expect(stranger.status).toBe(403);
    const unverified = await oidcSignIn({ sub: 'idp-y', email: 'frank@acme.test', email_verified: false });
    expect(unverified.error).toMatch(/not verified/);
  });

  // ---- trusted devices ---------------------------------------------------------------------

  it('releases the user key to a trusted device only after a fresh SSO sign-in', async () => {
    const deviceId = uuid();
    const pair = generateX25519();
    const auth = { authorization: `Bearer ${newbie.login.accessToken}` };
    const trust = await app.inject({
      method: 'POST',
      url: '/api/devices/trust',
      headers: auth,
      payload: { id: deviceId, name: 'Laptop', publicKey: toB64(pair.publicKey), protectedUserKey: sealUserKeyForDevice(toB64(pair.publicKey), newbie.password.keys.userKey, newbie.id, deviceId) },
    });
    expect(trust.statusCode).toBe(204);

    const r = await oidcSignIn({ sub: 'idp-user-1', email: 'dana@acme.test' }, { deviceId, previousRefreshToken: newbie.login.refreshToken });
    if (r.body.status !== 'authenticated') throw new Error(`unexpected ${r.body.status}`);
    const userKey = openDeviceUserKey(pair.privateKey, r.body.login.deviceKey!, newbie.id, deviceId);
    expect(userKey).toEqual(newbie.password.keys.userKey);
    // The locked session it replaced was ended.
    expect((await app.inject({ method: 'POST', url: '/api/auth/refresh', payload: { refreshToken: newbie.login.refreshToken } })).statusCode).toBe(401);
    newbie.login = r.body.login;

    // Password logins never release device keys; unknown devices get nothing.
    const other = await oidcSignIn({ sub: 'idp-user-1', email: 'dana@acme.test' }, { deviceId: uuid() });
    expect(other.body.status === 'authenticated' && other.body.login.deviceKey).toBe(null);
  });

  it('approves a new device from an unlocked one, and admin approval needs account recovery', async () => {
    const auth = { authorization: `Bearer ${newbie.login.accessToken}` };
    const phone = generateX25519();
    const id = uuid();
    const req = await app.inject({ method: 'POST', url: '/api/devices/request', headers: auth, payload: { id, name: 'Phone', publicKey: toB64(phone.publicKey) } });
    expect(req.statusCode).toBe(201);
    expect(req.json()).toMatchObject({ status: 'pending', protectedUserKey: null });

    // Someone else's session can't approve it.
    const foreign = await app.inject({ method: 'POST', url: `/api/devices/${id}/approve`, headers: carol.auth, payload: { protectedUserKey: sealUserKeyForDevice(toB64(phone.publicKey), carol.keys.userKey, carol.id, id) } });
    expect(foreign.statusCode).toBe(404);

    const approve = await app.inject({
      method: 'POST',
      url: `/api/devices/${id}/approve`,
      headers: auth,
      payload: { protectedUserKey: sealUserKeyForDevice(toB64(phone.publicKey), newbie.password.keys.userKey, newbie.id, id) },
    });
    expect(approve.statusCode).toBe(204);
    const polled = (await app.inject({ method: 'GET', url: `/api/devices/${id}`, headers: auth })).json();
    expect(openDeviceUserKey(phone.privateKey, polled.protectedUserKey, newbie.id, id)).toEqual(newbie.password.keys.userKey);

    const adminReq = await app.inject({
      method: 'POST',
      url: '/api/devices/request',
      headers: carol.auth,
      payload: { id: uuid(), name: 'Tablet', publicKey: toB64(generateX25519().publicKey), adminOrgId: acme },
    });
    expect(adminReq.statusCode).toBe(403); // Carol isn't confirmed yet (and isn't enrolled in recovery)
  });

  it('forces members (not owners) to use SSO when the organization enforces it', async () => {
    // Confirm Dana so she's a full member, then enforce SSO.
    const members = (await app.inject({ method: 'GET', url: `/api/orgs/${acme}/members`, headers: alice.auth })).json() as OrgMember[];
    const dana = members.find((m) => m.email === 'dana@acme.test')!;
    await app.inject({
      method: 'POST',
      url: `/api/orgs/${acme}/members/${dana.id}/confirm`,
      headers: alice.auth,
      payload: { protectedOrgKey: sealOrgKey(dana.publicKey!, acmeKey, acme) },
    });
    expect((await app.inject({ method: 'PUT', url: `/api/orgs/${acme}/sso`, headers: alice.auth, payload: oidcConfig({ enforce: true }) })).statusCode).toBe(200);

    const blocked = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: 'dana@acme.test', authHash: newbie.password.payload.authHash } });
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json().error).toBe('sso_required');
    // A wrong password still reads as a wrong password (no information leak).
    const wrong = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: 'dana@acme.test', authHash: 'A'.repeat(43) } });
    expect(wrong.statusCode).toBe(401);
    // Owners keep password sign-in as a break-glass path.
    const pre = (await app.inject({ method: 'POST', url: '/api/auth/prelogin', payload: { email: 'alice@acme.test' } })).json();
    const { authHash } = await deriveLoginSecrets('alice@acme.test-master-password', fromB64(pre.salt), pre.kdf);
    expect((await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: 'alice@acme.test', authHash } })).statusCode).toBe(200);
    await app.inject({ method: 'PUT', url: `/api/orgs/${acme}/sso`, headers: alice.auth, payload: oidcConfig({ enforce: false }) });
  });

  // ---- SAML ----------------------------------------------------------------------------------

  describe('SAML 2.0', () => {
    const acs = `https://vault.example.test/api/sso/saml/${globex}/acs`;
    const audience = `https://vault.example.test/api/sso/saml/${globex}`;

    async function samlStart() {
      const b = binding();
      const start = await app.inject({ method: 'POST', url: '/api/sso/start', payload: { identifier: 'globex', binding: b.hash } });
      expect(start.statusCode).toBe(200);
      const url = new URL(start.json().redirectUrl);
      expect(url.origin + url.pathname).toBe('https://idp.example.test/sso');
      const relay = url.searchParams.get('RelayState')!;
      const { rows } = await db.query('SELECT saml_request_id FROM sso_transactions WHERE id = $1', [relay]);
      return { relay, requestId: rows[0].saml_request_id as string, b };
    }

    async function post(relay: string | undefined, SAMLResponse: string) {
      const form = new URLSearchParams({ SAMLResponse, ...(relay ? { RelayState: relay } : {}) }).toString();
      const res = await app.inject({ method: 'POST', url: `/api/sso/saml/${globex}/acs`, headers: { 'content-type': 'application/x-www-form-urlencoded' }, payload: form });
      expect(res.statusCode).toBe(303);
      return new URLSearchParams(new URL(res.headers.location as string).hash.slice(1));
    }

    beforeAll(async () => {
      const put = await app.inject({
        method: 'PUT',
        url: `/api/orgs/${globex}/sso`,
        headers: bob.auth,
        payload: {
          enabled: true,
          identifier: 'globex',
          jitProvisioning: true,
          enforce: false,
          groupSync: false,
          settings: { type: 'saml', idpEntityId: IDP_ENTITY, ssoUrl: 'https://idp.example.test/sso', certificate: SAML_CERT, groupsAttribute: 'groups' },
        },
      });
      expect(put.statusCode).toBe(200);
      await app.inject({ method: 'POST', url: `/api/orgs/${globex}/members/invite`, headers: bob.auth, payload: { emails: ['gina@globex-partner.test'], role: 'member' } });
    });

    it('publishes SP metadata', async () => {
      const res = await app.inject({ method: 'GET', url: `/api/sso/saml/${globex}/metadata` });
      expect(res.body).toContain(`entityID="${audience}"`);
      expect(res.body).toContain(acs);
    });

    it('accepts a signed assertion that answers our own request', async () => {
      const { relay, requestId, b } = await samlStart();
      const frag = await post(relay, samlResponse({ acs, audience, inResponseTo: requestId, email: 'gina@globex-partner.test' }));
      expect(frag.get('error')).toBeNull();
      const res = await app.inject({ method: 'POST', url: '/api/sso/exchange', payload: { code: frag.get('code'), bindingSecret: b.secret } });
      expect(res.json()).toMatchObject({ status: 'provision', email: 'gina@globex-partner.test', orgName: 'Globex' });

      // Replaying the same response is refused (the transaction is spent).
      const replay = await post(relay, samlResponse({ acs, audience, inResponseTo: requestId, email: 'gina@globex-partner.test' }));
      expect(replay.get('error')).toBeTruthy();
    });

    it('rejects tampered, unsolicited, mismatched and foreign-audience responses', async () => {
      let t = await samlStart();
      expect((await post(t.relay, samlResponse({ acs, audience, inResponseTo: t.requestId, email: 'gina@globex-partner.test', tamper: true }))).get('error')).toMatch(/rejected/);

      t = await samlStart();
      expect((await post(undefined, samlResponse({ acs, audience, inResponseTo: t.requestId, email: 'gina@globex-partner.test' }))).get('error')).toMatch(/initiated/);

      t = await samlStart();
      expect((await post(t.relay, samlResponse({ acs, audience, inResponseTo: '_someone_elses_request', email: 'gina@globex-partner.test' }))).get('error')).toMatch(/rejected/);

      t = await samlStart();
      expect((await post(t.relay, samlResponse({ acs, audience: 'https://other-sp.test', inResponseTo: t.requestId, email: 'gina@globex-partner.test' }))).get('error')).toMatch(/rejected/);
    });
  });

  // ---- SCIM ----------------------------------------------------------------------------------

  describe('SCIM 2.0', () => {
    let token = '';
    const scim = (method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', url: string, payload?: unknown, bearer = token) =>
      app.inject({
        method,
        url: `/api/scim/v2${url}`,
        headers: { authorization: `Bearer ${bearer}`, ...(payload ? { 'content-type': 'application/scim+json' } : {}) },
        ...(payload ? { payload: JSON.stringify(payload) } : {}),
      });
    let userId = '';
    let groupId = '';

    beforeAll(async () => {
      const res = await app.inject({ method: 'POST', url: `/api/orgs/${acme}/scim-tokens`, headers: alice.auth, payload: { name: 'Okta' } });
      expect(res.statusCode).toBe(201);
      token = res.json().token;
      expect(token).toMatch(/^enc_scim_/);
    });

    it('requires a valid token and serves discovery documents', async () => {
      expect((await scim('GET', '/Users', undefined, 'enc_scim_nope')).statusCode).toBe(401);
      const cfg = await scim('GET', '/ServiceProviderConfig');
      expect(cfg.statusCode).toBe(200);
      expect(cfg.headers['content-type']).toMatch(/application\/scim\+json/);
      expect(cfg.json().patch.supported).toBe(true);
    });

    it('provisions a user as an invitation', async () => {
      outbox.length = 0;
      const res = await scim('POST', '/Users', {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: 'Hank@Acme.test',
        externalId: 'okta-hank',
        name: { givenName: 'Hank', familyName: 'Hill' },
        emails: [{ value: 'hank@acme.test', primary: true }],
        active: true,
      });
      expect(res.statusCode).toBe(201);
      const user = res.json();
      userId = user.id;
      expect(user).toMatchObject({ userName: 'hank@acme.test', externalId: 'okta-hank', active: true, displayName: 'Hank Hill' });
      expect(outbox.map((m) => m.to)).toContain('hank@acme.test');
      expect((await scim('POST', '/Users', { userName: 'hank@acme.test' })).statusCode).toBe(409);

      const found = (await scim('GET', `/Users?filter=${encodeURIComponent('userName eq "hank@acme.test"')}`)).json();
      expect(found).toMatchObject({ totalResults: 1, Resources: [{ id: userId }] });
      expect((await scim('GET', `/Users?filter=${encodeURIComponent('externalId eq "okta-hank"')}`)).json().totalResults).toBe(1);
      expect((await scim('GET', `/Users?filter=${encodeURIComponent('title sw "x"')}`)).statusCode).toBe(400);
    });

    it('deprovisions with an Entra-style PATCH and re-activates', async () => {
      const off = await scim('PATCH', `/Users/${userId}`, {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [{ op: 'Replace', path: 'active', value: 'False' }],
      });
      expect(off.statusCode).toBe(200);
      expect(off.json().active).toBe(false);
      const members = (await app.inject({ method: 'GET', url: `/api/orgs/${acme}/members`, headers: alice.auth })).json() as OrgMember[];
      expect(members.find((m) => m.id === userId)).toMatchObject({ revoked: true, scimManaged: true });

      const on = await scim('PATCH', `/Users/${userId}`, { Operations: [{ op: 'replace', value: { active: true } }] });
      expect(on.json().active).toBe(true);
    });

    it('never lets the IdP deactivate the last owner', async () => {
      const owner = ((await app.inject({ method: 'GET', url: `/api/orgs/${acme}/members`, headers: alice.auth })).json() as OrgMember[]).find((m) => m.role === 'owner')!;
      const res = await scim('PATCH', `/Users/${owner.id}`, { Operations: [{ op: 'replace', path: 'active', value: false }] });
      expect(res.statusCode).toBe(400);
      expect(res.json().scimType).toBe('mutability');
    });

    it('manages groups and their members', async () => {
      const res = await scim('POST', '/Groups', { displayName: 'Finance', externalId: 'okta-finance', members: [{ value: userId }] });
      expect(res.statusCode).toBe(201);
      groupId = res.json().id;
      expect(res.json().members).toHaveLength(1);

      const remove = await scim('PATCH', `/Groups/${groupId}`, { Operations: [{ op: 'remove', path: `members[value eq "${userId}"]` }] });
      expect(remove.statusCode).toBe(204);
      expect((await scim('GET', `/Groups/${groupId}`)).json().members).toHaveLength(0);

      await scim('PATCH', `/Groups/${groupId}`, { Operations: [{ op: 'add', path: 'members', value: [{ value: userId }] }, { op: 'replace', path: 'displayName', value: 'Finance & Ops' }] });
      const g = (await scim('GET', `/Groups?filter=${encodeURIComponent('displayName eq "Finance & Ops"')}`)).json();
      expect(g.Resources[0]).toMatchObject({ id: groupId, externalId: 'okta-finance', members: [{ value: userId }] });

      // Members of another tenant can't be added.
      const foreign = ((await app.inject({ method: 'GET', url: `/api/orgs/${globex}/members`, headers: bob.auth })).json() as OrgMember[])[0]!;
      expect((await scim('PATCH', `/Groups/${groupId}`, { Operations: [{ op: 'add', path: 'members', value: [{ value: foreign.id }] }] })).statusCode).toBe(400);
    });

    it('is confined to the token’s organization', async () => {
      const globexMember = ((await app.inject({ method: 'GET', url: `/api/orgs/${globex}/members`, headers: bob.auth })).json() as OrgMember[])[0]!;
      expect((await scim('GET', `/Users/${globexMember.id}`)).statusCode).toBe(404);
      expect((await scim('DELETE', `/Users/${globexMember.id}`)).statusCode).toBe(404);
      const all = (await scim('GET', '/Users')).json();
      expect(all.Resources.every((u: { userName: string }) => !u.userName.endsWith('@globex.test'))).toBe(true);
    });

    it('deletes users and groups, and revoked tokens stop working', async () => {
      expect((await scim('DELETE', `/Groups/${groupId}`)).statusCode).toBe(204);
      expect((await scim('DELETE', `/Users/${userId}`)).statusCode).toBe(204);
      expect((await scim('GET', `/Users/${userId}`)).statusCode).toBe(404);

      const tokens = (await app.inject({ method: 'GET', url: `/api/orgs/${acme}/scim-tokens`, headers: alice.auth })).json();
      expect(tokens[0].lastUsedAt).not.toBeNull();
      expect(tokens[0].token).toBeUndefined();
      await app.inject({ method: 'DELETE', url: `/api/orgs/${acme}/scim-tokens/${tokens[0].id}`, headers: alice.auth });
      expect((await scim('GET', '/Users')).statusCode).toBe(401);
    });
  });
});
