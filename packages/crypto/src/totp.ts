import { hmac } from '@noble/hashes/hmac';
import { sha1 } from '@noble/hashes/legacy';
import { sha256, sha512 } from '@noble/hashes/sha2';

export interface TotpConfig {
  secret: Uint8Array;
  digits: number;
  period: number;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input: string): Uint8Array {
  const s = input.toUpperCase().replace(/[\s=-]/g, '');
  const out: number[] = [];
  let buf = 0;
  let bits = 0;
  for (const ch of s) {
    const v = B32.indexOf(ch);
    if (v < 0) throw new Error('Invalid base32 secret');
    buf = (buf << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** Accepts a bare base32 secret or an otpauth://totp/... URI. */
export function parseTotp(value: string): TotpConfig {
  const v = value.trim();
  if (v.toLowerCase().startsWith('otpauth://')) {
    const url = new URL(v);
    const alg = (url.searchParams.get('algorithm') ?? 'SHA1').toUpperCase();
    return {
      secret: base32Decode(url.searchParams.get('secret') ?? ''),
      digits: Number(url.searchParams.get('digits') ?? 6),
      period: Number(url.searchParams.get('period') ?? 30),
      algorithm: alg === 'SHA256' || alg === 'SHA512' ? alg : 'SHA1',
    };
  }
  return { secret: base32Decode(v), digits: 6, period: 30, algorithm: 'SHA1' };
}

/** RFC 6238 time-based one-time password. */
export function totpCode(cfg: TotpConfig, nowMs = Date.now()): { code: string; remaining: number } {
  if (cfg.secret.length === 0) throw new Error('Empty TOTP secret');
  const counter = Math.floor(nowMs / 1000 / cfg.period);
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const hash = cfg.algorithm === 'SHA256' ? sha256 : cfg.algorithm === 'SHA512' ? sha512 : sha1;
  const mac = hmac(hash, cfg.secret, msg);
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin =
    ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  const code = String(bin % 10 ** cfg.digits).padStart(cfg.digits, '0');
  const remaining = cfg.period - (Math.floor(nowMs / 1000) % cfg.period);
  return { code, remaining };
}

export function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let buf = 0;
  let bits = 0;
  for (const b of bytes) {
    buf = (buf << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(buf >> bits) & 31];
    }
  }
  if (bits > 0) out += B32[(buf << (5 - bits)) & 31];
  return out;
}

/**
 * Checks a code against the current time step ±`window` steps (clock skew).
 * Returns the matching time-step counter so callers can reject replays, or null.
 */
export function verifyTotp(cfg: TotpConfig, code: string, nowMs = Date.now(), window = 1): number | null {
  const clean = code.replace(/\s+/g, '');
  if (!/^\d+$/.test(clean) || clean.length !== cfg.digits) return null;
  const step = Math.floor(nowMs / 1000 / cfg.period);
  for (let d = -window; d <= window; d++) {
    const at = (step + d) * cfg.period * 1000;
    if (totpCode(cfg, at).code === clean) return step + d;
  }
  return null;
}
