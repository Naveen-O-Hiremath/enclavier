import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { fromB64, toB64, utf8 } from './encoding';
import { randomBytes } from './random';

/**
 * Serialized ciphertext: `e1.<alg>.<nonce>.<ciphertext+tag>` (base64url).
 * alg "x" = XChaCha20-Poly1305. The version/alg prefix enables crypto agility.
 */
export type EncString = string;

export class DecryptionError extends Error {
  constructor(message = 'Decryption failed') {
    super(message);
    this.name = 'DecryptionError';
  }
}

const VERSION = 'e1';
const ALG_XCHACHA = 'x';
const NONCE_LEN = 24;

function aadBytes(aad?: string): Uint8Array | undefined {
  return aad === undefined ? undefined : utf8.encode(aad);
}

function assertKey(key: Uint8Array): void {
  if (key.length !== 32) throw new Error('Key must be 32 bytes');
}

export function encryptBytes(key: Uint8Array, plaintext: Uint8Array, aad?: string): EncString {
  assertKey(key);
  const nonce = randomBytes(NONCE_LEN);
  const ct = xchacha20poly1305(key, nonce, aadBytes(aad)).encrypt(plaintext);
  return `${VERSION}.${ALG_XCHACHA}.${toB64(nonce)}.${toB64(ct)}`;
}

export function decryptBytes(key: Uint8Array, enc: EncString, aad?: string): Uint8Array {
  assertKey(key);
  const parts = enc.split('.');
  if (parts.length !== 4 || parts[0] !== VERSION || parts[1] !== ALG_XCHACHA) {
    throw new DecryptionError('Unsupported ciphertext format');
  }
  try {
    const nonce = fromB64(parts[2]!);
    if (nonce.length !== NONCE_LEN) throw new Error('bad nonce');
    return xchacha20poly1305(key, nonce, aadBytes(aad)).decrypt(fromB64(parts[3]!));
  } catch {
    throw new DecryptionError();
  }
}

export function encryptString(key: Uint8Array, plaintext: string, aad?: string): EncString {
  return encryptBytes(key, utf8.encode(plaintext), aad);
}

export function decryptString(key: Uint8Array, enc: EncString, aad?: string): string {
  return utf8.decode(decryptBytes(key, enc, aad));
}

export function encryptJson(key: Uint8Array, value: unknown, aad?: string): EncString {
  return encryptString(key, JSON.stringify(value), aad);
}

export function decryptJson<T>(key: Uint8Array, enc: EncString, aad?: string): T {
  return JSON.parse(decryptString(key, enc, aad)) as T;
}

export function isEncString(v: unknown): v is EncString {
  return typeof v === 'string' && /^e1\.x\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
}
