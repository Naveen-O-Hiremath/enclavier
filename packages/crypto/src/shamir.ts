import { sha256 } from '@noble/hashes/sha2';
import { fromB64, toB64, utf8 } from './encoding';
import { randomBytes } from './random';

// Shamir's Secret Sharing over GF(2^8) (AES field, polynomial x^8+x^4+x^3+x+1).
// Any `threshold` shares reconstruct the secret; fewer reveal nothing about it.

const EXP = new Uint8Array(510);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    // multiply by the generator 3: x ^ xtime(x)
    x ^= ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff;
  }
  for (let i = 255; i < 510; i++) EXP[i] = EXP[i - 255]!;
}

const mul = (a: number, b: number) => (a === 0 || b === 0 ? 0 : EXP[LOG[a]! + LOG[b]!]!);
const div = (a: number, b: number) => {
  if (b === 0) throw new Error('Division by zero');
  return a === 0 ? 0 : EXP[(LOG[a]! + 255 - LOG[b]!) % 255]!;
};

export interface Share {
  /** 1..255 */
  x: number;
  y: Uint8Array;
}

export function splitSecret(secret: Uint8Array, shares: number, threshold: number): Share[] {
  if (!Number.isInteger(threshold) || threshold < 2) throw new Error('Threshold must be at least 2');
  if (!Number.isInteger(shares) || shares < threshold || shares > 255) throw new Error('Shares must be between threshold and 255');
  const out: Share[] = Array.from({ length: shares }, (_, i) => ({ x: i + 1, y: new Uint8Array(secret.length) }));
  for (let b = 0; b < secret.length; b++) {
    const coeffs = randomBytes(threshold - 1);
    for (const s of out) {
      // Horner: a0 + x(a1 + x(a2 + ...))
      let y = 0;
      for (let c = coeffs.length - 1; c >= 0; c--) y = mul(y ^ coeffs[c]!, s.x);
      s.y[b] = y ^ secret[b]!;
    }
    coeffs.fill(0);
  }
  return out;
}

export function combineShares(shares: Share[]): Uint8Array {
  if (shares.length < 2) throw new Error('At least two shares are required');
  const xs = shares.map((s) => s.x);
  if (new Set(xs).size !== xs.length) throw new Error('Duplicate shares');
  const len = shares[0]!.y.length;
  if (shares.some((s) => s.y.length !== len)) throw new Error('Shares have different lengths');
  const secret = new Uint8Array(len);
  for (let b = 0; b < len; b++) {
    let acc = 0;
    for (let i = 0; i < shares.length; i++) {
      // Lagrange basis at 0: prod_{j != i} x_j / (x_j - x_i); subtraction is XOR in GF(2^8).
      let basis = 1;
      for (let j = 0; j < shares.length; j++) {
        if (i !== j) basis = mul(basis, div(xs[j]!, xs[j]! ^ xs[i]!));
      }
      acc ^= mul(shares[i]!.y[b]!, basis);
    }
    secret[b] = acc;
  }
  return secret;
}

// ---- printable share format ---------------------------------------------------

export interface EncodedShareInfo {
  kitId: string;
  threshold: number;
  share: Share;
}

const PREFIX = 'ENCLAVIER-SHARE-1';

function checksum(body: string): string {
  return Array.from(sha256(utf8.encode(body)).slice(0, 3), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/** `ENCLAVIER-SHARE-1.<kitId>.<threshold>.<x>.<data>.<checksum>`; the checksum catches typos. */
export function encodeShare(kitId: string, threshold: number, share: Share): string {
  const body = `${PREFIX}.${kitId}.${threshold}.${share.x}.${toB64(share.y)}`;
  return `${body}.${checksum(body)}`;
}

export function decodeShare(text: string): EncodedShareInfo {
  const clean = text.replace(/\s+/g, '');
  const parts = clean.split('.');
  if (parts.length !== 6 || parts[0] !== PREFIX) throw new Error('Not an Enclavier recovery share');
  const body = parts.slice(0, 5).join('.');
  if (checksum(body) !== parts[5]!.toUpperCase()) throw new Error('Share checksum mismatch — check for typos');
  const threshold = Number(parts[2]);
  const x = Number(parts[3]);
  if (!Number.isInteger(threshold) || threshold < 2 || !Number.isInteger(x) || x < 1 || x > 255) throw new Error('Malformed share');
  return { kitId: parts[1]!, threshold, share: { x, y: fromB64(parts[4]!) } };
}
