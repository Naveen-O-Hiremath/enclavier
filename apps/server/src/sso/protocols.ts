import { randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import * as oidc from 'openid-client';
import { SAML, ValidateInResponseTo, generateServiceProviderMetadata, type CacheProvider } from '@node-saml/node-saml';
import type { SsoSettings } from '@enclavier/shared';
import { privateHostProblem } from '../net';
import { serviceProvider } from './store';

type OidcSettings = Extract<SsoSettings, { type: 'oidc' }>;
type SamlSettings = Extract<SsoSettings, { type: 'saml' }>;

/** What the IdP asserted, after all signatures and bindings were checked. */
export interface SsoIdentity {
  subject: string;
  email: string;
  name: string;
  groups: string[];
}

export class SsoError extends Error {}

export const newState = () => randomBytes(32).toString('base64url');

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normaliseEmail(value: unknown): string {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!EMAIL.test(email) || email.length > 254) throw new SsoError('The identity provider did not send a valid e-mail address');
  return email;
}

function stringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string').slice(0, 500);
  return typeof value === 'string' && value ? [value] : [];
}

// ---- OpenID Connect ---------------------------------------------------------------------

const discoveryCache = new Map<string, { at: number; config: oidc.Configuration }>();
const DISCOVERY_TTL_MS = 10 * 60 * 1000;

/** Every request to an admin-configured IdP goes through this guard (SSRF). */
function guardedFetch(allowPrivate: boolean): oidc.CustomFetch {
  return async (url, options) => {
    const u = new URL(url);
    if (!allowPrivate) {
      if (u.protocol !== 'https:') throw new SsoError('The identity provider must use https');
      const problem = await privateHostProblem(u.hostname);
      if (problem) throw new SsoError(`${problem}. Set ALLOW_PRIVATE_SSO_ENDPOINTS=true on self-hosted servers to allow an internal identity provider.`);
    }
    return fetch(url, { ...options, redirect: 'manual', signal: AbortSignal.timeout(10_000) } as RequestInit);
  };
}

export async function oidcConfiguration(app: FastifyInstance, s: OidcSettings): Promise<oidc.Configuration> {
  const allowPrivate = app.config.ALLOW_PRIVATE_SSO_ENDPOINTS;
  // The network policy is part of the key: a cached configuration must never bypass the SSRF guard.
  const key = JSON.stringify([s.issuer, s.clientId, s.clientSecret ?? '', allowPrivate]);
  const hit = discoveryCache.get(key);
  if (hit && Date.now() - hit.at < DISCOVERY_TTL_MS) return hit.config;
  let config: oidc.Configuration;
  try {
    config = await oidc.discovery(new URL(s.issuer), s.clientId, s.clientSecret || undefined, s.clientSecret ? undefined : oidc.None(), {
      [oidc.customFetch]: guardedFetch(allowPrivate),
      execute: allowPrivate ? [oidc.allowInsecureRequests] : [],
      timeout: 10,
    });
  } catch (err) {
    // openid-client wraps errors from the fetch guard; show the admin the real reason.
    let reason = err as Error;
    while (!(reason instanceof SsoError) && reason?.cause instanceof Error) reason = reason.cause;
    throw new SsoError(`Could not load the OpenID configuration from ${s.issuer}: ${(reason instanceof SsoError ? reason : (err as Error)).message}`);
  }
  if (discoveryCache.size > 500) discoveryCache.clear();
  discoveryCache.set(key, { at: Date.now(), config });
  return config;
}

export async function beginOidc(app: FastifyInstance, s: OidcSettings, state: string) {
  const config = await oidcConfiguration(app, s);
  const nonce = oidc.randomNonce();
  const codeVerifier = oidc.randomPKCECodeVerifier();
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: serviceProvider(app.config, '').redirectUri,
    scope: s.scopes || 'openid email profile',
    state,
    nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
  });
  return { url: url.href, nonce, codeVerifier };
}

export async function completeOidc(
  app: FastifyInstance,
  s: OidcSettings,
  txn: { id: string; nonce: string; codeVerifier: string },
  query: Record<string, string>,
): Promise<SsoIdentity> {
  const config = await oidcConfiguration(app, s);
  const current = new URL(serviceProvider(app.config, '').redirectUri);
  for (const [k, v] of Object.entries(query)) current.searchParams.set(k, v);
  let claims: oidc.IDToken | undefined;
  try {
    const tokens = await oidc.authorizationCodeGrant(config, current, {
      pkceCodeVerifier: txn.codeVerifier,
      expectedState: txn.id,
      expectedNonce: txn.nonce,
      idTokenExpected: true,
    });
    claims = tokens.claims();
  } catch (err) {
    throw new SsoError(`The identity provider rejected the sign-in: ${(err as Error).message}`);
  }
  if (!claims) throw new SsoError('The identity provider did not return an ID token');
  if (s.emailClaim === 'email' && claims.email_verified === false) {
    throw new SsoError('The identity provider says this e-mail address is not verified');
  }
  const email = normaliseEmail(claims[s.emailClaim]);
  const given = [claims.given_name, claims.family_name].filter((v) => typeof v === 'string').join(' ');
  return {
    subject: claims.sub,
    email,
    name: (typeof claims.name === 'string' && claims.name) || given || email.split('@')[0]!,
    groups: s.groupsClaim ? stringList(claims[s.groupsClaim]) : [],
  };
}

// ---- SAML 2.0 ---------------------------------------------------------------------------

function certificates(input: string): string[] {
  const pems = input.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (pems?.length) return pems;
  return [input.replace(/\s+/g, '')];
}

/**
 * The request ID "cache" is the transaction itself: a response is accepted
 * only if it answers the exact AuthnRequest this browser started
 * (IdP-initiated and replayed responses are rejected).
 */
function transactionCache(expectedRequestId: string | null, onSave?: (id: string) => void): CacheProvider {
  return {
    saveAsync: async (key, value) => {
      onSave?.(key);
      return { value, createdAt: Date.now() };
    },
    getAsync: async (key) => (expectedRequestId && key === expectedRequestId ? new Date().toISOString() : null),
    removeAsync: async () => null,
  };
}

function samlClient(app: FastifyInstance, orgId: string, s: SamlSettings, cache: CacheProvider): SAML {
  const sp = serviceProvider(app.config, orgId);
  return new SAML({
    entryPoint: s.ssoUrl,
    issuer: sp.entityId,
    callbackUrl: sp.acsUrl,
    audience: sp.entityId,
    idpIssuer: s.idpEntityId,
    idpCert: certificates(s.certificate),
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    identifierFormat: null,
    disableRequestedAuthnContext: true,
    acceptedClockSkewMs: 120_000,
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: 10 * 60 * 1000,
    cacheProvider: cache,
  });
}

export async function beginSaml(app: FastifyInstance, orgId: string, s: SamlSettings, state: string) {
  let requestId = '';
  const saml = samlClient(app, orgId, s, transactionCache(null, (id) => (requestId = id)));
  const url = await saml.getAuthorizeUrlAsync(state, undefined, {});
  if (!requestId) throw new SsoError('Could not create the SAML request');
  return { url, requestId };
}

export async function completeSaml(
  app: FastifyInstance,
  orgId: string,
  s: SamlSettings,
  requestId: string,
  body: { SAMLResponse: string; RelayState?: string },
): Promise<SsoIdentity> {
  const saml = samlClient(app, orgId, s, transactionCache(requestId));
  let profile;
  try {
    ({ profile } = await saml.validatePostResponseAsync({ SAMLResponse: body.SAMLResponse, RelayState: body.RelayState ?? '' }));
  } catch (err) {
    throw new SsoError(`The SAML response was rejected: ${(err as Error).message}`);
  }
  if (!profile?.nameID) throw new SsoError('The SAML response has no subject');
  const attr = (name: string) => (name ? profile[name] : undefined);
  const email = normaliseEmail(attr(s.emailAttribute) ?? profile.email ?? profile.mail ?? profile['urn:oid:0.9.2342.19200300.100.1.3'] ?? profile.nameID);
  const nameValue = attr(s.nameAttribute);
  return {
    subject: profile.nameID,
    email,
    name: (typeof nameValue === 'string' && nameValue) || email.split('@')[0]!,
    groups: s.groupsAttribute ? stringList(attr(s.groupsAttribute)) : [],
  };
}

export function samlMetadata(app: FastifyInstance, orgId: string): string {
  const sp = serviceProvider(app.config, orgId);
  return generateServiceProviderMetadata({ issuer: sp.entityId, callbackUrl: sp.acsUrl, wantAssertionsSigned: true } as Parameters<
    typeof generateServiceProviderMetadata
  >[0]);
}
