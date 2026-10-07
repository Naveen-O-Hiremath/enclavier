import {
  decryptItem,
  deriveLoginSecrets,
  encryptItem,
  fromB64,
  lockKeys,
  openOrgKey,
  toB64,
  unlockAccount,
  unlockWithKek,
  updateItem,
  uuid,
  wipe,
  type AccountKeyBundle,
  type UnlockedKeys,
} from '@enclavier/crypto';
import type {
  Item,
  ItemData,
  LoginResponse,
  LoginResult,
  OrgPolicies,
  Permission,
  PreloginResponse,
  Profile,
  SyncResponse,
  TokenResponse,
  TwoFactorMethod,
} from '@enclavier/shared';
import type { ExtState, Status } from '../shared/messages';

/**
 * Where things live:
 *  - chrome.storage.local   server URL, refresh token, profile, encrypted key bundle (like the web vault's localStorage)
 *  - chrome.storage.session unlocked account keys + access token: memory only, never written to disk,
 *                           readable only by extension pages (not content scripts), gone when the browser closes
 *  - module memory          decrypted items (rebuilt from the session keys when the service worker restarts)
 */

interface Persisted {
  serverUrl: string;
  refreshToken: string;
  profile: Profile;
  bundle: AccountKeyBundle;
  lockMinutes: number;
}

export interface VaultEntry {
  id: string;
  orgId: string | null;
  collectionId: string | null;
  folderId: string | null;
  key: string;
  revision: number;
  permission: Permission;
  data: ItemData;
}

const LOCAL = 'enclavier';
const SESSION = 'enclavier.keys';

let keys: UnlockedKeys | null = null;
let accessToken: string | null = null;
let entries: VaultEntry[] = [];
let orgNames = new Map<string, string>();
let orgPolicies: OrgPolicies[] = [];
let loaded: Promise<void> | null = null;
let pending2fa: { email: string; challengeToken: string; methods: TwoFactorMethod[]; webauthn: boolean } | null = null;

async function readLocal(): Promise<Persisted | null> {
  return ((await chrome.storage.local.get(LOCAL))[LOCAL] as Persisted | undefined) ?? null;
}

async function writeLocal(p: Persisted | null) {
  if (p) await chrome.storage.local.set({ [LOCAL]: p });
  else await chrome.storage.local.remove(LOCAL);
}

async function saveSessionKeys() {
  if (!keys) {
    await chrome.storage.session.remove(SESSION);
    return;
  }
  await chrome.storage.session.set({
    [SESSION]: { userKey: toB64(keys.userKey), privateKey: toB64(keys.privateKey), publicKey: toB64(keys.publicKey), accessToken },
  });
}

/** Restores the unlocked state after the service worker was suspended. */
export function ensureLoaded(): Promise<void> {
  loaded ??= (async () => {
    // Content scripts must never read the session area (it holds keys).
    await chrome.storage.session.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' }).catch(() => undefined);
    const s = (await chrome.storage.session.get(SESSION))[SESSION] as
      | { userKey: string; privateKey: string; publicKey: string; accessToken: string | null }
      | undefined;
    if (s && (await readLocal())) {
      keys = { userKey: fromB64(s.userKey), privateKey: fromB64(s.privateKey), publicKey: fromB64(s.publicKey) };
      accessToken = s.accessToken;
      try {
        await sync();
      } catch {
        // Offline: stay unlocked with an empty list until the next sync.
      }
    }
  })();
  return loaded;
}

// ---- API ------------------------------------------------------------------------------

class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

async function raw(serverUrl: string, method: string, path: string, body?: unknown, token?: string | null) {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  try {
    return await fetch(`${serverUrl}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'omit', cache: 'no-store' });
  } catch {
    throw new ApiError(0, 'network', `Cannot reach ${serverUrl}. Check the server address and that Enclavier may access it.`);
  }
}

async function toError(res: Response) {
  try {
    const b = (await res.json()) as { error?: string; message?: string };
    return new ApiError(res.status, b.error ?? 'error', b.message ?? res.statusText);
  } catch {
    return new ApiError(res.status, 'error', res.statusText || 'Request failed');
  }
}

async function refresh(): Promise<boolean> {
  const p = await readLocal();
  if (!p) return false;
  const res = await raw(p.serverUrl, 'POST', '/api/auth/refresh', { refreshToken: p.refreshToken });
  if (!res.ok) return false;
  const t = (await res.json()) as TokenResponse;
  accessToken = t.accessToken;
  await writeLocal({ ...p, refreshToken: t.refreshToken });
  await saveSessionKeys();
  return true;
}

async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const p = await readLocal();
  if (!p) throw new Error('Not signed in');
  if (!accessToken) await refresh();
  let res = await raw(p.serverUrl, method, path, body, accessToken);
  if (res.status === 401) {
    if (await refresh()) res = await raw(p.serverUrl, method, path, body, accessToken);
    if (res.status === 401) {
      await clearAll();
      throw new Error('Your session ended. Sign in again.');
    }
  }
  if (!res.ok) throw await toError(res);
  return (res.status === 204 ? undefined : await res.json()) as T;
}

// ---- state ------------------------------------------------------------------------------

export async function state(): Promise<ExtState> {
  await ensureLoaded();
  const p = await readLocal();
  const status: Status = !p ? 'loggedOut' : keys ? 'unlocked' : 'locked';
  return {
    status,
    serverUrl: p?.serverUrl ?? null,
    email: p?.profile.email ?? pending2fa?.email ?? null,
    name: p?.profile.name ?? null,
    twoFactor: pending2fa ? { methods: pending2fa.methods, webauthn: pending2fa.webauthn } : null,
    lockMinutes: effectiveLockMinutes(p?.lockMinutes ?? 15),
  };
}

/** Organization vault-timeout policies cap the user's own choice. */
export function effectiveLockMinutes(chosen: number): number {
  const caps = orgPolicies.map((p) => p.vaultTimeout?.maxMinutes).filter((m): m is number => typeof m === 'number');
  if (!caps.length) return chosen;
  const cap = Math.min(...caps);
  return chosen === 0 ? cap : Math.min(chosen, cap);
}

export function clipboardSeconds(): number {
  const caps = orgPolicies.map((p) => p.clipboard?.maxSeconds).filter((m): m is number => typeof m === 'number');
  return caps.length ? Math.min(30, ...caps) : 30;
}

export async function setLockMinutes(minutes: number) {
  const p = await readLocal();
  if (p) await writeLocal({ ...p, lockMinutes: minutes });
}

async function clearAll() {
  lockKeys(keys);
  keys = null;
  accessToken = null;
  entries = [];
  pending2fa = null;
  await saveSessionKeys();
  await writeLocal(null);
}

// ---- sign-in -------------------------------------------------------------------------------

let pendingKek: Uint8Array | null = null;

function deviceName(): string {
  const firefox = navigator.userAgent.includes('Firefox');
  return `Browser extension · ${firefox ? 'Firefox' : navigator.userAgent.includes('Edg/') ? 'Edge' : 'Chrome'}`;
}

async function establish(serverUrl: string, res: LoginResponse, unlocked: UnlockedKeys) {
  keys = unlocked;
  accessToken = res.accessToken;
  const previous = await readLocal();
  await writeLocal({ serverUrl, refreshToken: res.refreshToken, profile: res.profile, bundle: res.keys, lockMinutes: previous?.lockMinutes ?? 15 });
  await saveSessionKeys();
  await sync();
}

export async function login(serverUrl: string, email: string, password: string): Promise<'unlocked' | '2fa'> {
  const base = serverUrl.replace(/\/+$/, '');
  const pre = await raw(base, 'POST', '/api/auth/prelogin', { email });
  if (!pre.ok) throw await toError(pre);
  const { kdf, salt } = (await pre.json()) as PreloginResponse;
  const { kek, authHash } = await deriveLoginSecrets(password, fromB64(salt), kdf);
  const res = await raw(base, 'POST', '/api/auth/login', { email, authHash, deviceName: deviceName() });
  if (!res.ok) {
    wipe(kek);
    throw await toError(res);
  }
  const result = (await res.json()) as LoginResult;
  if ('twoFactorRequired' in result) {
    const methods = result.methods.filter((m) => m !== 'webauthn');
    pendingKek = kek;
    pending2fa = { email, challengeToken: result.challengeToken, methods, webauthn: result.methods.includes('webauthn') };
    await chrome.storage.local.set({ 'enclavier.pendingServer': base });
    return '2fa';
  }
  try {
    await establish(base, result, unlockWithKek(kek, result.keys));
  } finally {
    wipe(kek);
  }
  return 'unlocked';
}

export async function completeTwoFactor(method: TwoFactorMethod, code: string) {
  if (!pending2fa || !pendingKek) throw new Error('Your sign-in attempt expired. Start again.');
  const base = ((await chrome.storage.local.get('enclavier.pendingServer'))['enclavier.pendingServer'] as string) ?? '';
  const res = await raw(base, 'POST', '/api/auth/login/2fa', { challengeToken: pending2fa.challengeToken, method, code, deviceName: deviceName() });
  if (!res.ok) throw await toError(res);
  const login = (await res.json()) as LoginResponse;
  const kek = pendingKek;
  pendingKek = null;
  pending2fa = null;
  try {
    await establish(base, login, unlockWithKek(kek, login.keys));
  } finally {
    wipe(kek);
  }
}

export function cancelTwoFactor() {
  if (pendingKek) wipe(pendingKek);
  pendingKek = null;
  pending2fa = null;
}

export async function unlock(password: string) {
  const p = await readLocal();
  if (!p) throw new Error('Not signed in');
  keys = await unlockAccount(password, p.bundle); // throws InvalidPasswordError
  await saveSessionKeys();
  await sync();
}

export async function lock() {
  lockKeys(keys);
  keys = null;
  entries = [];
  for (const k of orgKeys.values()) wipe(k);
  orgKeys.clear();
  await saveSessionKeys();
}

export async function logout() {
  try {
    if (await readLocal()) await api('POST', '/api/auth/logout');
  } catch {
    // best effort
  }
  await clearAll();
}

export const isUnlocked = () => !!keys;

export async function serverUrl(): Promise<string | null> {
  return (await readLocal())?.serverUrl ?? null;
}

// ---- vault -----------------------------------------------------------------------------------

const orgKeys = new Map<string, Uint8Array>();

export async function sync() {
  if (!keys) throw new Error('Vault is locked');
  const res = await api<SyncResponse>('GET', '/api/sync');
  for (const k of orgKeys.values()) wipe(k);
  orgKeys.clear();
  orgNames = new Map();
  orgPolicies = [];
  for (const o of res.organizations) {
    orgNames.set(o.id, o.name);
    if (o.status === 'confirmed') orgPolicies.push(o.policies);
    if (!o.protectedOrgKey) continue;
    try {
      orgKeys.set(o.id, openOrgKey(keys.privateKey, o.protectedOrgKey, o.id));
    } catch {
      // unreadable org key = no access
    }
  }
  const perms = new Map(res.collections.map((c) => [c.id, c.permission]));
  const next: VaultEntry[] = [];
  for (const it of res.items as Item[]) {
    if (it.deletedAt) continue;
    const ownerKey = it.orgId ? orgKeys.get(it.orgId) : keys.userKey;
    if (!ownerKey) continue;
    try {
      next.push({
        id: it.id,
        orgId: it.orgId,
        collectionId: it.collectionId,
        folderId: it.folderId,
        key: it.key,
        revision: it.revision,
        permission: it.orgId ? (perms.get(it.collectionId ?? '') ?? 'use') : 'manage',
        data: decryptItem<ItemData>(ownerKey, it),
      });
    } catch {
      // tampered or corrupted items are skipped
    }
  }
  entries = next;
  const p = await readLocal();
  if (p) await writeLocal({ ...p, profile: res.profile, bundle: res.keys });
}

export const allEntries = () => entries;
export const orgName = (id: string | null) => (id ? (orgNames.get(id) ?? 'Organization') : null);
export const findEntry = (id: string) => entries.find((e) => e.id === id);

const RANK: Record<Permission, number> = { use: 1, view: 2, edit: 3, manage: 4 };

/** Saves a new login to the personal vault. */
export async function saveLogin(input: { name: string; uri: string; username: string; password: string }) {
  if (!keys) throw new Error('Vault is locked');
  const data: ItemData = { type: 'login', name: input.name, login: { username: input.username, password: input.password, uris: [input.uri] } };
  await api('POST', '/api/items', encryptItem(keys.userKey, uuid(), null, data));
  await sync();
}

/** Updates the password of an existing login (keeps the old one in its history). */
export async function updatePassword(id: string, password: string) {
  if (!keys) throw new Error('Vault is locked');
  const e = findEntry(id);
  if (!e || e.data.type !== 'login') throw new Error('Item not found');
  if (RANK[e.permission] < RANK.edit) throw new Error('You can only use this shared item, not change it');
  const old = e.data.login?.password;
  const data: ItemData = {
    ...e.data,
    login: { ...e.data.login, password },
    passwordHistory: old ? [{ password: old, changedAt: new Date().toISOString() }, ...(e.data.passwordHistory ?? [])].slice(0, 10) : e.data.passwordHistory,
  };
  if (e.orgId) {
    const orgKey = orgKeys.get(e.orgId);
    if (!orgKey) throw new Error('No access to this organization');
    await api('PUT', `/api/orgs/${e.orgId}/items/${e.id}`, { collectionId: e.collectionId, data: updateItem(orgKey, e, data), revision: e.revision });
  } else {
    await api('PUT', `/api/items/${e.id}`, { folderId: e.folderId, data: updateItem(keys.userKey, e, data), revision: e.revision });
  }
  await sync();
}
