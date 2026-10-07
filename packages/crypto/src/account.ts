import { publicKeyFromPrivate, generateKeyPair } from './asymmetric';
import { fromB64, toB64, wipe } from './encoding';
import { DEFAULT_KDF, deriveMasterKey, hkdfExpand, KDF_INFO, type KdfParams } from './kdf';
import { randomBytes } from './random';
import { decryptBytes, DecryptionError, encryptBytes, type EncString } from './symmetric';

const AAD = {
  userKey: 'enclavier/user-key',
  privateKey: 'enclavier/private-key',
} as const;

/** What the server stores (and returns) — ciphertext and public data only. */
export interface AccountKeyBundle {
  kdf: KdfParams;
  /** base64url, 16 bytes */
  salt: string;
  protectedUserKey: EncString;
  /** base64url X25519 public key */
  publicKey: string;
  protectedPrivateKey: EncString;
}

export interface RegistrationPayload extends AccountKeyBundle {
  /** base64url HKDF(masterKey, "auth") — proves knowledge of the password without revealing it. */
  authHash: string;
}

/** Keys held in memory while the vault is unlocked. Never persisted, never sent. */
export interface UnlockedKeys {
  userKey: Uint8Array;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface LoginSecrets {
  kek: Uint8Array;
  authHash: string;
}

export async function deriveLoginSecrets(password: string, salt: Uint8Array, kdf: KdfParams): Promise<LoginSecrets> {
  const masterKey = await deriveMasterKey(password, salt, kdf);
  try {
    return {
      kek: hkdfExpand(masterKey, KDF_INFO.kek, salt),
      authHash: toB64(hkdfExpand(masterKey, KDF_INFO.auth, salt)),
    };
  } finally {
    wipe(masterKey);
  }
}

/** Creates all key material for a new account. */
export async function createAccount(
  password: string,
  kdf: KdfParams = DEFAULT_KDF,
): Promise<{ payload: RegistrationPayload; keys: UnlockedKeys }> {
  const salt = randomBytes(16);
  const { kek, authHash } = await deriveLoginSecrets(password, salt, kdf);
  const userKey = randomBytes(32);
  const pair = generateKeyPair();
  try {
    return {
      payload: {
        kdf,
        salt: toB64(salt),
        authHash,
        protectedUserKey: encryptBytes(kek, userKey, AAD.userKey),
        publicKey: toB64(pair.publicKey),
        protectedPrivateKey: encryptBytes(userKey, pair.privateKey, AAD.privateKey),
      },
      keys: { userKey, privateKey: pair.privateKey, publicKey: pair.publicKey },
    };
  } finally {
    wipe(kek);
  }
}

export class InvalidPasswordError extends Error {
  constructor() {
    super('Invalid master password');
    this.name = 'InvalidPasswordError';
  }
}

/** Unwraps the account keys with the key-encryption key derived from the master password. */
export function unlockWithKek(kek: Uint8Array, bundle: AccountKeyBundle): UnlockedKeys {
  let userKey: Uint8Array;
  try {
    userKey = decryptBytes(kek, bundle.protectedUserKey, AAD.userKey);
  } catch (e) {
    if (e instanceof DecryptionError) throw new InvalidPasswordError();
    throw e;
  }
  const privateKey = decryptBytes(userKey, bundle.protectedPrivateKey, AAD.privateKey);
  const publicKey = publicKeyFromPrivate(privateKey);
  if (toB64(publicKey) !== bundle.publicKey) throw new Error('Account key pair mismatch');
  return { userKey, privateKey, publicKey };
}

/** Unwraps the account keys from an already-recovered user key (trusted device, device approval). */
export function unlockWithUserKey(userKey: Uint8Array, bundle: AccountKeyBundle): UnlockedKeys {
  const privateKey = decryptBytes(userKey, bundle.protectedPrivateKey, AAD.privateKey);
  const publicKey = publicKeyFromPrivate(privateKey);
  if (toB64(publicKey) !== bundle.publicKey) throw new Error('Account key pair mismatch');
  return { userKey, privateKey, publicKey };
}

/** Local unlock: no network round trip, fails with InvalidPasswordError on a wrong password. */
export async function unlockAccount(password: string, bundle: AccountKeyBundle): Promise<UnlockedKeys> {
  const { kek } = await deriveLoginSecrets(password, fromB64(bundle.salt), bundle.kdf);
  try {
    return unlockWithKek(kek, bundle);
  } finally {
    wipe(kek);
  }
}

export interface PasswordChangePayload {
  kdf: KdfParams;
  salt: string;
  authHash: string;
  protectedUserKey: EncString;
}

/** Re-wraps the existing user key under a new master password. The vault itself is untouched. */
export async function rewrapUserKey(
  keys: Pick<UnlockedKeys, 'userKey'>,
  newPassword: string,
  kdf: KdfParams = DEFAULT_KDF,
): Promise<PasswordChangePayload> {
  const salt = randomBytes(16);
  const { kek, authHash } = await deriveLoginSecrets(newPassword, salt, kdf);
  try {
    return { kdf, salt: toB64(salt), authHash, protectedUserKey: encryptBytes(kek, keys.userKey, AAD.userKey) };
  } finally {
    wipe(kek);
  }
}

export function lockKeys(keys: UnlockedKeys | null | undefined): void {
  if (keys) wipe(keys.userKey, keys.privateKey);
}
