import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { concatBytes, fromB64, toB64, wipe } from './encoding';
import { hkdfExpand, KDF_INFO } from './kdf';
import { randomBytes } from './random';
import { decryptBytes, encryptBytes } from './symmetric';

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const privateKey = randomBytes(32);
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function publicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

/**
 * Anonymous sealed box: encrypt to a recipient public key.
 * Format: `s1.<ephemeral pub>.<EncString>`; the symmetric key is
 * HKDF(ECDH(eph, recipient), salt = eph_pub ‖ recipient_pub).
 */
export function seal(recipientPublicKey: Uint8Array, plaintext: Uint8Array, aad?: string): string {
  const eph = generateKeyPair();
  const shared = x25519.getSharedSecret(eph.privateKey, recipientPublicKey);
  const key = hkdfExpand(shared, KDF_INFO.seal, concatBytes(eph.publicKey, recipientPublicKey));
  try {
    return `s1.${toB64(eph.publicKey)}.${encryptBytes(key, plaintext, aad)}`;
  } finally {
    wipe(shared, key, eph.privateKey);
  }
}

export function unseal(privateKey: Uint8Array, sealed: string, aad?: string): Uint8Array {
  const firstDot = sealed.indexOf('.');
  const secondDot = sealed.indexOf('.', firstDot + 1);
  if (sealed.slice(0, firstDot) !== 's1' || secondDot < 0) throw new Error('Unsupported sealed format');
  const ephPub = fromB64(sealed.slice(firstDot + 1, secondDot));
  const recipientPub = x25519.getPublicKey(privateKey);
  const shared = x25519.getSharedSecret(privateKey, ephPub);
  const key = hkdfExpand(shared, KDF_INFO.seal, concatBytes(ephPub, recipientPub));
  try {
    return decryptBytes(key, sealed.slice(secondDot + 1), aad);
  } finally {
    wipe(shared, key);
  }
}

/** Human-verifiable fingerprint of a public key (used when sharing keys out of band). */
export function fingerprint(publicKey: Uint8Array): string {
  const hex = Array.from(sha256(publicKey).slice(0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{4}/g)!.join('-');
}
