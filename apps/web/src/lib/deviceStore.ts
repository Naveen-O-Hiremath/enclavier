import { fromB64, generateKeyPair, toB64 } from '@enclavier/crypto';

/**
 * Per-browser device identities for trusted-device SSO unlock.
 *
 * The X25519 private key is stored wrapped with an AES-GCM key that is
 * non-extractable and lives in IndexedDB: script on this origin can use it,
 * but it can't be read out or copied to another machine from a profile dump
 * of localStorage alone. The unwrapped key is only useful after a fresh SSO
 * sign-in, when the server releases the user key sealed to this device.
 */

export interface DeviceEntry {
  deviceId: string;
  userId: string;
  email: string;
  publicKey: string;
  /** base64url AES-GCM(iv ‖ ciphertext) of the private key. */
  wrapped: string;
  status: 'pending' | 'trusted';
  sso?: { id: string; name: string; identifier: string };
}

const INDEX_KEY = 'enclavier.devices';
const DB = 'enclavier-device-keys';

function readIndex(): Record<string, DeviceEntry> {
  try {
    return JSON.parse(localStorage.getItem(INDEX_KEY) ?? '{}') as Record<string, DeviceEntry>;
  } catch {
    return {};
  }
}

function writeIndex(index: Record<string, DeviceEntry>) {
  try {
    localStorage.setItem(INDEX_KEY, JSON.stringify(index));
  } catch {
    // Storage blocked: trusted-device unlock simply isn't available.
  }
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore('keys');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idb<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = fn(db.transaction('keys', mode).objectStore('keys'));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

async function wrappingKey(): Promise<CryptoKey> {
  const existing = await idb<CryptoKey | undefined>('readonly', (s) => s.get('wrap') as IDBRequest<CryptoKey | undefined>);
  if (existing) return existing;
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  await idb('readwrite', (s) => s.put(key, 'wrap'));
  return key;
}

async function wrap(privateKey: Uint8Array): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await wrappingKey(), new Uint8Array(privateKey)));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return toB64(out);
}

export async function unwrapDeviceKey(entry: DeviceEntry): Promise<Uint8Array> {
  const raw = fromB64(entry.wrapped);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, await wrappingKey(), raw.slice(12));
  return new Uint8Array(plain);
}

export function deviceFor(email: string): DeviceEntry | null {
  return readIndex()[email.toLowerCase()] ?? null;
}

/** Creates a fresh device key pair for this account (replacing any previous one). */
export async function newDevice(user: { id: string; email: string }, deviceId: string): Promise<{ entry: DeviceEntry; privateKey: Uint8Array }> {
  const pair = generateKeyPair();
  const entry: DeviceEntry = {
    deviceId,
    userId: user.id,
    email: user.email.toLowerCase(),
    publicKey: toB64(pair.publicKey),
    wrapped: await wrap(pair.privateKey),
    status: 'pending',
  };
  return { entry, privateKey: pair.privateKey };
}

export function saveDevice(entry: DeviceEntry) {
  const index = readIndex();
  index[entry.email] = entry;
  writeIndex(index);
}

export function forgetDevice(email: string) {
  const index = readIndex();
  delete index[email.toLowerCase()];
  writeIndex(index);
}

export function deviceLabel(): string {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : 'device';
  return `${browser} on ${os}`;
}
