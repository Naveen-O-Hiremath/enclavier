import { parse } from 'tldts';

/**
 * Autofill matching. A saved website matches a page when both share the same
 * registrable domain (public-suffix aware: `a.example.co.uk` ≠ `b.co.uk`).
 * Credentials saved for https are never offered to plain-http pages, and
 * IP/localhost entries must match exactly (including the port).
 */

export function normaliseUri(uri: string): URL | null {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(uri) ? uri : `https://${uri}`;
  try {
    const u = new URL(withScheme);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u : null;
  } catch {
    return null;
  }
}

function site(u: URL): string {
  const p = parse(u.hostname, { allowPrivateDomains: true });
  if (p.isIp || !p.domain) return u.host; // IPs, localhost, intranet names: exact host:port
  return p.domain;
}

export function uriMatches(saved: string, pageUrl: string): boolean {
  const s = normaliseUri(saved);
  const page = normaliseUri(pageUrl);
  if (!s || !page) return false;
  if (s.protocol === 'https:' && page.protocol !== 'https:') return false; // downgrade
  return site(s) === site(page);
}

/** Exact-host matches rank above same-site matches. */
export function matchScore(saved: string, pageUrl: string): number {
  if (!uriMatches(saved, pageUrl)) return 0;
  const s = normaliseUri(saved)!;
  const page = normaliseUri(pageUrl)!;
  return s.host === page.host ? 2 : 1;
}

export function originOf(url: string): string | null {
  const u = normaliseUri(url);
  return u ? u.origin : null;
}

export function hostOf(url: string): string {
  return normaliseUri(url)?.hostname ?? url;
}
