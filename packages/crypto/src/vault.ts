import { wipe } from './encoding';
import { randomBytes } from './random';
import { decryptBytes, decryptJson, decryptString, encryptBytes, encryptJson, encryptString, type EncString } from './symmetric';

/** Server-side shape of an item: opaque ciphertext bound to its id. */
export interface EncryptedItem {
  id: string;
  folderId: string | null;
  /** itemKey wrapped by the owner key (user key now, collection key in Phase 2). */
  key: EncString;
  /** JSON payload encrypted with itemKey. */
  data: EncString;
}

const itemKeyAad = (id: string) => `item-key:${id}`;
const itemDataAad = (id: string) => `item:${id}`;
const folderAad = (id: string) => `folder:${id}`;

export function encryptItem<T>(ownerKey: Uint8Array, id: string, folderId: string | null, value: T): EncryptedItem {
  const itemKey = randomBytes(32);
  try {
    return {
      id,
      folderId,
      key: encryptBytes(ownerKey, itemKey, itemKeyAad(id)),
      data: encryptJson(itemKey, value, itemDataAad(id)),
    };
  } finally {
    wipe(itemKey);
  }
}

/** Re-encrypts item data with its existing item key (edits keep the key stable). */
export function updateItem<T>(ownerKey: Uint8Array, item: Pick<EncryptedItem, 'id' | 'key'>, value: T): EncString {
  const itemKey = decryptBytes(ownerKey, item.key, itemKeyAad(item.id));
  try {
    return encryptJson(itemKey, value, itemDataAad(item.id));
  } finally {
    wipe(itemKey);
  }
}

export function decryptItem<T>(ownerKey: Uint8Array, item: Pick<EncryptedItem, 'id' | 'key' | 'data'>): T {
  const itemKey = decryptBytes(ownerKey, item.key, itemKeyAad(item.id));
  try {
    return decryptJson<T>(itemKey, item.data, itemDataAad(item.id));
  } finally {
    wipe(itemKey);
  }
}

export function encryptFolderName(userKey: Uint8Array, id: string, name: string): EncString {
  return encryptString(userKey, name, folderAad(id));
}

export function decryptFolderName(userKey: Uint8Array, id: string, enc: EncString): string {
  return decryptString(userKey, enc, folderAad(id));
}
