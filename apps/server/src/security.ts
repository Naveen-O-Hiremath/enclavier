import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { SignJWT, jwtVerify } from 'jose';

const scryptAsync = promisify(scrypt) as (pw: Buffer, salt: Buffer, len: number, opts: object) => Promise<Buffer>;

// The client already sends Argon2id-derived material; this server-side hash
// ensures a database leak does not directly yield a replayable login secret.
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export async function hashAuthSecret(authHash: string): Promise<string> {
  const salt = randomBytes(16);
  const dk = await scryptAsync(Buffer.from(authHash, 'utf8'), salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64url')}$${dk.toString('base64url')}`;
}

export async function verifyAuthSecret(authHash: string, stored: string): Promise<boolean> {
  const [alg, n, r, p, salt, hash] = stored.split('$');
  if (alg !== 'scrypt' || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64url');
  const dk = await scryptAsync(Buffer.from(authHash, 'utf8'), Buffer.from(salt, 'base64url'), expected.length, {
    N: Number(n),
    r: Number(r),
    p: Number(p),
    maxmem: SCRYPT.maxmem,
  });
  return timingSafeEqual(dk, expected);
}

/** Burns the same CPU as a real verification so unknown e-mails are not distinguishable by timing. */
let dummyHash: Promise<string> | undefined;
export async function dummyVerify(authHash: string): Promise<void> {
  dummyHash ??= hashAuthSecret('enclavier-dummy');
  await verifyAuthSecret(authHash, await dummyHash);
}

/** Deterministic per-email fake salt for /prelogin on unknown accounts (anti-enumeration). */
export function fakeSalt(serverSecret: string, email: string): string {
  return createHmac('sha256', serverSecret).update(`prelogin:${email}`).digest().subarray(0, 16).toString('base64url');
}

export function newRefreshToken(): string {
  return randomBytes(32).toString('base64url');
}

export function sha256(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

export interface AccessClaims {
  sub: string;
  sid: string;
}

export class TokenService {
  private readonly key: Uint8Array;

  constructor(secret: string, private readonly ttlSeconds: number) {
    this.key = new TextEncoder().encode(secret);
  }

  get ttl(): number {
    return this.ttlSeconds;
  }

  sign(claims: AccessClaims): Promise<string> {
    return new SignJWT({ sid: claims.sid })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject(claims.sub)
      .setIssuer('enclavier')
      .setAudience('enclavier-api')
      .setIssuedAt()
      .setExpirationTime(`${this.ttlSeconds}s`)
      .sign(this.key);
  }

  async verify(token: string): Promise<AccessClaims> {
    const { payload } = await jwtVerify(token, this.key, {
      issuer: 'enclavier',
      audience: 'enclavier-api',
      algorithms: ['HS256'],
    });
    if (typeof payload.sub !== 'string' || typeof payload.sid !== 'string') throw new Error('Malformed token');
    return { sub: payload.sub, sid: payload.sid };
  }
}

// ---- server-side secrets at rest -------------------------------------------------

/**
 * AES-256-GCM for server-held secrets (TOTP seeds). These are authentication
 * factors, not vault data, so the server must be able to read them — but a
 * database dump alone does not reveal them.
 */
export class SecretBox {
  private readonly key: Buffer;

  constructor(serverSecret: string) {
    this.key = Buffer.from(hkdfSync('sha256', serverSecret, 'enclavier', 'secret-box/v1', 32));
  }

  seal(plaintext: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return `v1.${Buffer.concat([iv, ct, cipher.getAuthTag()]).toString('base64url')}`;
  }

  open(sealed: string): string {
    const [version, body] = sealed.split('.');
    if (version !== 'v1' || !body) throw new Error('Unsupported sealed secret');
    const raw = Buffer.from(body, 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', this.key, raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    return Buffer.concat([decipher.update(raw.subarray(12, raw.length - 16)), decipher.final()]).toString('utf8');
  }
}

// ---- recovery codes -----------------------------------------------------------------

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I

export function newRecoveryCodes(count = 10): string[] {
  return Array.from({ length: count }, () => {
    const bytes = randomBytes(10);
    const chars = Array.from(bytes, (b) => CODE_ALPHABET[b & 31]).join('');
    return `${chars.slice(0, 5)}-${chars.slice(5)}`;
  });
}

export function hashRecoveryCode(code: string): Buffer {
  return sha256(`recovery:${code.toUpperCase().replace(/[^A-Z0-9]/g, '')}`);
}

// ---- purpose-bound short-lived tokens (2FA challenges, WebAuthn ceremonies) --------------

export type PurposeClaims = Record<string, string | number | boolean>;

export class PurposeTokens {
  private readonly key: Uint8Array;

  constructor(secret: string) {
    this.key = new TextEncoder().encode(`purpose:${secret}`);
  }

  sign(purpose: string, sub: string, claims: PurposeClaims, ttlSeconds: number): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject(sub)
      .setIssuer('enclavier')
      .setAudience(`enclavier-${purpose}`)
      .setIssuedAt()
      .setExpirationTime(`${ttlSeconds}s`)
      .sign(this.key);
  }

  async verify(purpose: string, token: string): Promise<{ sub: string; claims: PurposeClaims }> {
    const { payload } = await jwtVerify(token, this.key, { issuer: 'enclavier', audience: `enclavier-${purpose}`, algorithms: ['HS256'] });
    if (typeof payload.sub !== 'string') throw new Error('Malformed token');
    return { sub: payload.sub, claims: payload as unknown as PurposeClaims };
  }
}
