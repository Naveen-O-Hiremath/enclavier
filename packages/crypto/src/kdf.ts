import { argon2id } from 'hash-wasm';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { utf8 } from './encoding';

export interface KdfParams {
  algorithm: 'argon2id';
  /** Memory cost in KiB. */
  memory: number;
  /** Iterations (time cost). */
  iterations: number;
  parallelism: number;
}

/** Defaults exceed OWASP 2024 guidance (m=19 MiB, t=2, p=1). */
export const DEFAULT_KDF: KdfParams = {
  algorithm: 'argon2id',
  memory: 64 * 1024,
  iterations: 3,
  parallelism: 4,
};

/** Lower bounds the server and clients refuse to go below. */
export const MIN_KDF: KdfParams = {
  algorithm: 'argon2id',
  memory: 19 * 1024,
  iterations: 2,
  parallelism: 1,
};

export function assertKdfParams(p: KdfParams): void {
  if (p.algorithm !== 'argon2id') throw new Error('Unsupported KDF');
  if (p.memory < MIN_KDF.memory || p.memory > 1024 * 1024) throw new Error('KDF memory out of range');
  if (p.iterations < MIN_KDF.iterations || p.iterations > 20) throw new Error('KDF iterations out of range');
  if (p.parallelism < 1 || p.parallelism > 16) throw new Error('KDF parallelism out of range');
}

export type Argon2Impl = (password: Uint8Array, salt: Uint8Array, params: KdfParams) => Promise<Uint8Array>;

/** WASM Argon2id (browser, Node, extension, desktop). Mobile clients inject a native one. */
const wasmArgon2: Argon2Impl = (password, salt, params) =>
  argon2id({
    password,
    salt,
    parallelism: params.parallelism,
    iterations: params.iterations,
    memorySize: params.memory,
    hashLength: 32,
    outputType: 'binary',
  });

let argon2Impl: Argon2Impl = wasmArgon2;

export function setArgon2Implementation(impl: Argon2Impl): void {
  argon2Impl = impl;
}

/** masterKey = Argon2id(NFKC(password), salt). */
export async function deriveMasterKey(password: string, salt: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  assertKdfParams(params);
  if (salt.length < 16) throw new Error('Salt too short');
  const pw = utf8.encode(password.normalize('NFKC'));
  try {
    return await argon2Impl(pw, salt, params);
  } finally {
    pw.fill(0);
  }
}

export function hkdfExpand(ikm: Uint8Array, info: string, salt?: Uint8Array, length = 32): Uint8Array {
  return hkdf(sha256, ikm, salt, utf8.encode(info), length);
}

export const KDF_INFO = {
  kek: 'enclavier/v1/kek',
  auth: 'enclavier/v1/auth',
  seal: 'enclavier/v1/seal',
} as const;
