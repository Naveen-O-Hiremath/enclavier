import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

// ---- SSRF protection for outbound requests to admin-configured URLs ---------------------

export function isPrivateAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number) as [number, number];
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) || // link-local incl. cloud metadata 169.254.169.254
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) // CGNAT
    );
  }
  const v6 = ip.toLowerCase();
  if (v6.startsWith('::ffff:')) return isPrivateAddress(v6.slice(7));
  return v6 === '::' || v6 === '::1' || v6.startsWith('fc') || v6.startsWith('fd') || v6.startsWith('fe80') || v6.startsWith('ff');
}

/**
 * Returns why a host must not be contacted (it resolves to a private, loopback
 * or link-local address), or null when it is public.
 */
export async function privateHostProblem(host: string): Promise<string | null> {
  const bare = host.replace(/^\[|\]$/g, '');
  const addresses = isIP(bare) ? [bare] : (await lookup(bare, { all: true }).catch(() => [])).map((a) => a.address);
  if (addresses.length === 0) return `Cannot resolve ${bare}`;
  if (addresses.some(isPrivateAddress)) return `${bare} resolves to a private or internal address`;
  return null;
}
