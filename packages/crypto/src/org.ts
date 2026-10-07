import { fingerprint, seal, unseal } from './asymmetric';
import { fromB64, wipe } from './encoding';
import { randomBytes } from './random';
import { decryptBytes, decryptString, encryptBytes, encryptString, type EncString } from './symmetric';

const orgKeyAad = (orgId: string) => `org-key:${orgId}`;
const collectionAad = (id: string) => `collection:${id}`;
const itemKeyAad = (id: string) => `item-key:${id}`;

export function generateOrgKey(): Uint8Array {
  return randomBytes(32);
}

/** Seals the org key to a member's X25519 public key (base64url). */
export function sealOrgKey(memberPublicKey: string, orgKey: Uint8Array, orgId: string): string {
  return seal(fromB64(memberPublicKey), orgKey, orgKeyAad(orgId));
}

export function openOrgKey(privateKey: Uint8Array, protectedOrgKey: string, orgId: string): Uint8Array {
  const key = unseal(privateKey, protectedOrgKey, orgKeyAad(orgId));
  if (key.length !== 32) throw new Error('Invalid organization key');
  return key;
}

/** Fingerprint admins compare out of band before confirming a member. */
export function publicKeyFingerprint(publicKey: string): string {
  return fingerprint(fromB64(publicKey));
}

export function encryptCollectionName(orgKey: Uint8Array, collectionId: string, name: string): EncString {
  return encryptString(orgKey, name, collectionAad(collectionId));
}

export function decryptCollectionName(orgKey: Uint8Array, collectionId: string, enc: EncString): string {
  return decryptString(orgKey, enc, collectionAad(collectionId));
}

/**
 * Moves an item between owners (personal vault → organization) by re-wrapping
 * its item key. The item data ciphertext is untouched.
 */
export function rewrapItemKey(fromKey: Uint8Array, toKey: Uint8Array, itemId: string, wrapped: EncString): EncString {
  const itemKey = decryptBytes(fromKey, wrapped, itemKeyAad(itemId));
  try {
    return encryptBytes(toKey, itemKey, itemKeyAad(itemId));
  } finally {
    wipe(itemKey);
  }
}
