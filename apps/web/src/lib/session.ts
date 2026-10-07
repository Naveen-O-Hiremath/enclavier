import { create } from 'zustand';
import {
  createAccount,
  decryptCollectionName,
  decryptFolderName,
  decryptItem,
  deriveLoginSecrets,
  encryptFolderName,
  encryptItem,
  fingerprint,
  fromB64,
  openDeviceUserKey,
  sealUserKeyForDevice,
  unlockWithUserKey,
  lockKeys,
  openOrgKey,
  rewrapItemKey,
  rewrapUserKey,
  toB64,
  unlockAccount,
  unlockWithKek,
  updateItem as encryptUpdate,
  uuid,
  wipe,
  type AccountKeyBundle,
  type UnlockedKeys,
} from '@enclavier/crypto';
import type {
  AcceptInviteRequest,
  Folder,
  Item,
  ItemData,
  LoginResponse,
  LoginResult,
  OrgSummary,
  TwoFactorChallenge,
  TwoFactorMethod,
  Permission,
  PreloginResponse,
  Profile,
  SsoExchangeResult,
  SsoOrg,
  SyncResponse,
  TokenResponse,
  TrustedDevice,
} from '@enclavier/shared';
import { api, configureApi } from './api';
import { effectivePolicy } from './policy';
import { checkStrength } from './strength';
import { deviceFor, deviceLabel, forgetDevice, newDevice, saveDevice, unwrapDeviceKey } from './deviceStore';

export interface VaultItem {
  id: string;
  folderId: string | null;
  orgId: string | null;
  collectionId: string | null;
  /** The caller's effective permission; personal items are always "manage". */
  permission: Permission;
  key: string;
  revision: number;
  createdAt: string;
  revisionDate: string;
  deletedAt: string | null;
  data: ItemData;
}

export interface VaultFolder {
  id: string;
  name: string;
}

export interface VaultCollection {
  id: string;
  orgId: string;
  name: string;
  permission: Permission;
}

export type VaultOrg = Omit<OrgSummary, 'protectedOrgKey'>;

type Status = 'loggedOut' | 'locked' | 'unlocked';

interface Persisted {
  refreshToken: string;
  profile: Profile;
  bundle: AccountKeyBundle;
  /** Organization SSO last used on this device (enables "Unlock with SSO"). */
  sso?: SsoOrg;
}

/** What the SSO callback page shows next. */
export type SsoOutcome =
  | { kind: 'unlocked' }
  | { kind: 'locked' }
  | { kind: 'two_factor'; challenge: TwoFactorChallenge }
  | { kind: 'link'; email: string; orgName: string }
  | { kind: 'provision'; email: string; name: string; orgName: string; provisionToken: string; org: SsoOrg };

const SSO_START_KEY = 'enclavier.sso.start';
export const SSO_LINK_KEY = 'enclavier.sso.link';

export interface SaveItemInput {
  id?: string;
  folderId: string | null;
  /** null = personal vault. */
  collectionId: string | null;
  data: ItemData;
}

interface State {
  status: Status;
  profile: Profile | null;
  bundle: AccountKeyBundle | null;
  items: VaultItem[];
  folders: VaultFolder[];
  organizations: VaultOrg[];
  collections: VaultCollection[];
  syncing: boolean;
  /** Set when the master password used to unlock falls short of an org policy. */
  masterPasswordViolation: { minLength: number; minScore: number; sources: string[] } | null;
  /** Items whose ciphertext could not be decrypted (tampering or corruption). */
  corrupted: number;
  /** Organization SSO used to sign in on this device, if any. */
  sso: SsoOrg | null;

  register(email: string, name: string, password: string, invite?: AcceptInviteRequest): Promise<void>;
  /** Resolves to a challenge when a second factor is required, otherwise null (signed in). */
  login(email: string, password: string): Promise<TwoFactorChallenge | null>;
  completeTwoFactor(input: { method: TwoFactorMethod; code?: string; webauthnResponse?: Record<string, unknown> }): Promise<void>;
  cancelTwoFactor(): void;
  unlock(password: string): Promise<void>;
  lock(): void;
  logout(): Promise<void>;
  sync(): Promise<void>;

  saveItem(input: SaveItemInput): Promise<VaultItem>;
  trashItem(id: string): Promise<void>;
  restoreItem(id: string): Promise<void>;
  deleteItem(id: string): Promise<void>;
  saveFolder(input: { id?: string; name: string }): Promise<void>;
  deleteFolder(id: string): Promise<void>;

  changePassword(current: string, next: string): Promise<void>;
  verifyPassword(password: string): Promise<string>;
  deleteAccount(password: string): Promise<void>;

  // ---- single sign-on & trusted devices ----
  ssoStart(input: { email: string; identifier?: string }): Promise<void>;
  ssoComplete(code: string): Promise<SsoOutcome>;
  ssoProvision(provisionToken: string, org: SsoOrg, name: string, password: string): Promise<void>;
  /** Whether this browser holds a trusted device key for the signed-in account. */
  isTrustedDevice(): boolean;
  trustThisDevice(): Promise<void>;
  forgetThisDevice(): Promise<void>;
  requestDeviceApproval(adminOrgId?: string): Promise<{ deviceId: string; fingerprint: string }>;
  /** Polls a pending approval; unlocks the vault once another device or an admin approved it. */
  checkDeviceApproval(): Promise<'pending' | 'approved' | 'denied'>;
  approveDevice(device: TrustedDevice): Promise<void>;
  /** Remembers the SSO organization for this device (after linking an account). */
  rememberSso(org: SsoOrg): void;
}

// ---- in-memory secrets (never in React state, never persisted) -------------

let keys: UnlockedKeys | null = null;
const orgKeys = new Map<string, Uint8Array>();
let accessToken: string | null = null;
/** Length and strength of the master password last used on this device (never the password itself). */
let masterStats: { length: number; score: number } | null = null;

async function measureMasterPassword(password: string): Promise<void> {
  try {
    masterStats = { length: [...password].length, score: (await checkStrength(password)).score };
  } catch {
    masterStats = null;
  }
}

/** Between the first factor and the second: the KEK (password logins) or the SSO organization. */
let pendingLogin: { kek: Uint8Array | null; challenge: TwoFactorChallenge; sso?: SsoOrg } | null = null;

function cancelPendingLogin() {
  if (pendingLogin?.kek) wipe(pendingLogin.kek);
  pendingLogin = null;
}

async function sha256b64(value: string): Promise<string> {
  return toB64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
}

const deviceName = () => `Web vault · ${navigator.platform || 'browser'}`;
const STORAGE_KEY = 'enclavier.session';

function readPersisted(): Persisted | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Persisted) : null;
  } catch {
    return null;
  }
}

function writePersisted(p: Persisted | null): void {
  if (p) localStorage.setItem(STORAGE_KEY, JSON.stringify(p));
  else localStorage.removeItem(STORAGE_KEY);
}

function requireKeys(): UnlockedKeys {
  if (!keys) throw new Error('Vault is locked');
  return keys;
}

export function requireAccountKeys(): UnlockedKeys {
  return requireKeys();
}

/** The decrypted org key, available only while unlocked and after an admin confirmed us. */
export function requireOrgKey(orgId: string): Uint8Array {
  const k = orgKeys.get(orgId);
  if (!k) throw new Error('You do not have access to this organization’s key yet');
  return k;
}

function wipeOrgKeys() {
  for (const k of orgKeys.values()) wipe(k);
  orgKeys.clear();
}

const itemUrl = (item: { id: string; orgId: string | null }) =>
  item.orgId ? `/api/orgs/${item.orgId}/items/${item.id}` : `/api/items/${item.id}`;

const initial = readPersisted();

export const useSession = create<State>((set, get) => {
  configureApi({
    getAccess: () => accessToken,
    getRefresh: () => readPersisted()?.refreshToken ?? null,
    save: (t: TokenResponse) => {
      accessToken = t.accessToken;
      const p = readPersisted();
      if (p) writePersisted({ ...p, refreshToken: t.refreshToken });
    },
    onSessionLost: () => clearLocal(),
  });

  const emptyVault = { items: [], folders: [], organizations: [], collections: [], corrupted: 0 };

  function clearLocal() {
    cancelPendingLogin();
    lockKeys(keys);
    keys = null;
    wipeOrgKeys();
    accessToken = null;
    writePersisted(null);
    set({ status: 'loggedOut', profile: null, bundle: null, sso: null, ...emptyVault });
  }

  function establish(res: LoginResponse, unlocked: UnlockedKeys | null, sso?: SsoOrg) {
    keys = unlocked;
    accessToken = res.accessToken;
    const previous = readPersisted();
    const keepSso = sso ?? (previous?.profile.id === res.profile.id ? previous?.sso : undefined);
    writePersisted({ refreshToken: res.refreshToken, profile: res.profile, bundle: res.keys, sso: keepSso });
    set({ status: unlocked ? 'unlocked' : 'locked', profile: res.profile, bundle: res.keys, sso: keepSso ?? null });
  }

  /**
   * An SSO sign-in proves identity but not the master password. The vault opens
   * directly only if this browser is a trusted device the server released the
   * user key to; otherwise the session starts locked (master password, or
   * approval from another device / an admin).
   */
  async function acceptSsoLogin(res: LoginResponse, org: SsoOrg | undefined): Promise<'unlocked' | 'locked'> {
    let unlocked: UnlockedKeys | null = null;
    const entry = deviceFor(res.profile.email);
    if (res.deviceKey && entry && entry.userId === res.profile.id && entry.status === 'trusted') {
      let privateKey: Uint8Array | null = null;
      try {
        privateKey = await unwrapDeviceKey(entry);
        unlocked = unlockWithUserKey(openDeviceUserKey(privateKey, res.deviceKey, res.profile.id, entry.deviceId), res.keys);
      } catch {
        unlocked = null; // stale device key: fall back to the other unlock methods
      } finally {
        if (privateKey) wipe(privateKey);
      }
    }
    establish(res, unlocked, org);
    if (unlocked) await get().sync();
    return unlocked ? 'unlocked' : 'locked';
  }

  function permissionFor(item: { orgId: string | null; collectionId: string | null }): Permission {
    if (!item.orgId) return 'manage';
    return get().collections.find((c) => c.id === item.collectionId)?.permission ?? 'use';
  }

  function decode(item: Item): VaultItem | null {
    const k = requireKeys();
    const ownerKey = item.orgId ? orgKeys.get(item.orgId) : k.userKey;
    if (!ownerKey) return null;
    try {
      return { ...item, permission: permissionFor(item), data: decryptItem<ItemData>(ownerKey, item) };
    } catch {
      return null;
    }
  }

  function applyItem(item: VaultItem) {
    set((s) => ({ items: [...s.items.filter((i) => i.id !== item.id), item] }));
  }

  function findItem(id: string): VaultItem {
    const item = get().items.find((i) => i.id === id);
    if (!item) throw new Error('Item not found');
    return item;
  }

  return {
    status: initial ? 'locked' : 'loggedOut',
    profile: initial?.profile ?? null,
    bundle: initial?.bundle ?? null,
    sso: initial?.sso ?? null,
    ...emptyVault,
    syncing: false,
    masterPasswordViolation: null,

    async register(email, name, password, invite) {
      const measured = measureMasterPassword(password);
      const { payload, keys: fresh } = await createAccount(password);
      await measured;
      const res = await api<LoginResponse>('POST', '/api/auth/register', { ...payload, email, name, invite }, { auth: false });
      establish(res, fresh);
      await get().sync();
    },

    async login(email, password) {
      cancelPendingLogin();
      const measured = measureMasterPassword(password);
      const pre = await api<PreloginResponse>('POST', '/api/auth/prelogin', { email }, { auth: false });
      const { kek, authHash } = await deriveLoginSecrets(password, fromB64(pre.salt), pre.kdf);
      await measured;
      let keep = false;
      try {
        const res = await api<LoginResult>('POST', '/api/auth/login', { email, authHash, deviceName: deviceName() }, { auth: false });
        if ('twoFactorRequired' in res) {
          // Hold the key-encryption key in memory only until the second factor completes.
          pendingLogin = { kek, challenge: res };
          keep = true;
          return res;
        }
        establish(res, unlockWithKek(kek, res.keys));
      } finally {
        if (!keep) wipe(kek);
      }
      await get().sync();
      return null;
    },

    async completeTwoFactor(input) {
      if (!pendingLogin) throw new Error('Your sign-in attempt expired. Enter your master password again.');
      const res = await api<LoginResponse>(
        'POST',
        '/api/auth/login/2fa',
        { challengeToken: pendingLogin.challenge.challengeToken, deviceName: deviceName(), ...input },
        { auth: false },
      );
      const { kek, sso } = pendingLogin;
      pendingLogin = null;
      if (!kek) {
        await acceptSsoLogin(res, sso);
        return;
      }
      try {
        establish(res, unlockWithKek(kek, res.keys));
      } finally {
        wipe(kek);
      }
      await get().sync();
    },

    cancelTwoFactor() {
      cancelPendingLogin();
    },

    async unlock(password) {
      const bundle = get().bundle;
      if (!bundle) throw new Error('No account on this device');
      const measured = measureMasterPassword(password);
      keys = await unlockAccount(password, bundle);
      await measured;
      set({ status: 'unlocked' });
      await get().sync();
    },

    lock() {
      lockKeys(keys);
      keys = null;
      wipeOrgKeys();
      set({ status: 'locked', ...emptyVault });
    },

    async logout() {
      try {
        if (accessToken || readPersisted()) await api('POST', '/api/auth/logout');
      } catch {
        // Best effort: local state is wiped regardless.
      }
      clearLocal();
    },

    async sync() {
      const k = requireKeys();
      set({ syncing: true });
      try {
        const res = await api<SyncResponse>('GET', '/api/sync');

        wipeOrgKeys();
        const organizations: VaultOrg[] = [];
        for (const { protectedOrgKey, ...org } of res.organizations) {
          organizations.push(org);
          if (!protectedOrgKey) continue;
          try {
            orgKeys.set(org.id, openOrgKey(k.privateKey, protectedOrgKey, org.id));
          } catch {
            // A key that fails to open is treated as "no access" (and items stay hidden).
          }
        }
        const collections: VaultCollection[] = res.collections.flatMap((c) => {
          const orgKey = orgKeys.get(c.orgId);
          if (!orgKey) return [];
          try {
            return [{ ...c, name: decryptCollectionName(orgKey, c.id, c.name) }];
          } catch {
            return [];
          }
        });
        // Org master-password policies are checked on the client: the server never sees the password.
        const mp = effectivePolicy(organizations).masterPassword;
        const violation = mp && masterStats && (masterStats.length < mp.minLength || masterStats.score < mp.minScore) ? mp : null;
        set({ organizations, collections, masterPasswordViolation: violation });

        const items: VaultItem[] = [];
        let corrupted = 0;
        for (const it of res.items) {
          const v = decode(it);
          if (v) items.push(v);
          else corrupted++;
        }
        const folders = res.folders.flatMap((f: Folder) => {
          try {
            return [{ id: f.id, name: decryptFolderName(k.userKey, f.id, f.name) }];
          } catch {
            return [];
          }
        });
        const p = readPersisted();
        if (p) writePersisted({ ...p, profile: res.profile, bundle: res.keys });
        set({ items, folders, corrupted, profile: res.profile, bundle: res.keys });
      } finally {
        set({ syncing: false });
      }
    },

    async saveItem({ id, folderId, collectionId, data }) {
      const k = requireKeys();
      const target = collectionId ? get().collections.find((c) => c.id === collectionId) : undefined;
      if (collectionId && !target) throw new Error('Collection not found');
      let existing = id ? findItem(id) : undefined;
      let saved: Item;

      if (!existing) {
        saved = target
          ? await api<Item>('POST', `/api/orgs/${target.orgId}/items`, {
              ...encryptItem(requireOrgKey(target.orgId), uuid(), null, data),
              collectionId: target.id,
            })
          : await api<Item>('POST', '/api/items', encryptItem(k.userKey, uuid(), folderId, data));
      } else if (existing.orgId) {
        if (!target || target.orgId !== existing.orgId) throw new Error('Organization items can only move between collections of the same organization');
        const orgKey = requireOrgKey(existing.orgId);
        saved = await api<Item>('PUT', itemUrl(existing), {
          collectionId: target.id,
          data: encryptUpdate(orgKey, existing, data),
          revision: existing.revision,
        });
      } else {
        // Personal item: save edits first, then (optionally) move it into a collection.
        saved = await api<Item>('PUT', itemUrl(existing), {
          folderId: target ? null : folderId,
          data: encryptUpdate(k.userKey, existing, data),
          revision: existing.revision,
        });
        if (target) {
          existing = { ...existing, revision: saved.revision };
          saved = await api<Item>('POST', `/api/items/${existing.id}/share`, {
            orgId: target.orgId,
            collectionId: target.id,
            key: rewrapItemKey(k.userKey, requireOrgKey(target.orgId), existing.id, existing.key),
            revision: existing.revision,
          });
        }
      }
      const item: VaultItem = { ...saved, permission: permissionFor(saved), data };
      applyItem(item);
      return item;
    },

    async trashItem(id) {
      const item = findItem(id);
      await api('DELETE', itemUrl(item));
      applyItem({ ...item, deletedAt: new Date().toISOString(), revision: item.revision + 1 });
    },

    async restoreItem(id) {
      const restored = decode(await api<Item>('POST', `${itemUrl(findItem(id))}/restore`));
      if (restored) applyItem(restored);
    },

    async deleteItem(id) {
      await api('DELETE', `${itemUrl(findItem(id))}?permanent=true`);
      set((s) => ({ items: s.items.filter((i) => i.id !== id) }));
    },

    async saveFolder({ id, name }) {
      const k = requireKeys();
      const folderId = id ?? uuid();
      const enc = encryptFolderName(k.userKey, folderId, name);
      if (id) await api('PUT', `/api/folders/${id}`, { name: enc });
      else await api('POST', '/api/folders', { id: folderId, name: enc });
      set((s) => ({ folders: [...s.folders.filter((f) => f.id !== folderId), { id: folderId, name }] }));
    },

    async deleteFolder(id) {
      await api('DELETE', `/api/folders/${id}`);
      set((s) => ({
        folders: s.folders.filter((f) => f.id !== id),
        items: s.items.map((i) => (i.folderId === id ? { ...i, folderId: null } : i)),
      }));
    },

    async verifyPassword(password) {
      const bundle = get().bundle;
      if (!bundle) throw new Error('Not signed in');
      const { kek, authHash } = await deriveLoginSecrets(password, fromB64(bundle.salt), bundle.kdf);
      try {
        const probe = unlockWithKek(kek, bundle); // throws InvalidPasswordError
        lockKeys(probe);
      } finally {
        wipe(kek);
      }
      return authHash;
    },

    async changePassword(current, next) {
      const currentAuthHash = await get().verifyPassword(current);
      const change = await rewrapUserKey(requireKeys(), next);
      await api('POST', '/api/account/password', { ...change, currentAuthHash });
      await measureMasterPassword(next);
      set({ masterPasswordViolation: null });
      const bundle = { ...get().bundle!, kdf: change.kdf, salt: change.salt, protectedUserKey: change.protectedUserKey };
      const profile = { ...get().profile!, forcePasswordChange: false };
      const p = readPersisted();
      if (p) writePersisted({ ...p, bundle, profile });
      set({ bundle, profile });
    },

    async deleteAccount(password) {
      const authHash = await get().verifyPassword(password);
      await api('POST', '/api/account/delete', { authHash });
      forgetDevice(get().profile?.email ?? '');
      clearLocal();
    },

    // ---- single sign-on & trusted devices ------------------------------------------

    async ssoStart({ email, identifier }) {
      const secret = toB64(crypto.getRandomValues(new Uint8Array(32)));
      const normalized = email.trim().toLowerCase();
      const res = await api<{ redirectUrl: string }>(
        'POST',
        '/api/sso/start',
        { email: normalized || undefined, identifier: identifier?.trim().toLowerCase() || undefined, binding: await sha256b64(secret) },
        { auth: false },
      );
      // Per-tab: the callback must come back to the same tab that started the sign-in.
      sessionStorage.setItem(SSO_START_KEY, JSON.stringify({ secret, email: normalized }));
      window.location.assign(res.redirectUrl);
    },

    async ssoComplete(code) {
      const started = JSON.parse(sessionStorage.getItem(SSO_START_KEY) ?? 'null') as { secret: string; email: string } | null;
      sessionStorage.removeItem(SSO_START_KEY);
      if (!started) throw new Error('This sign-in was started in another tab or window. Start again here.');
      const entry = started.email ? deviceFor(started.email) : null;
      const result = await api<SsoExchangeResult>(
        'POST',
        '/api/sso/exchange',
        {
          code,
          bindingSecret: started.secret,
          deviceId: entry?.status === 'trusted' ? entry.deviceId : undefined,
          deviceName: deviceName(),
          previousRefreshToken: readPersisted()?.refreshToken,
        },
        { auth: false },
      );
      switch (result.status) {
        case 'authenticated':
          return { kind: await acceptSsoLogin(result.login, result.org) };
        case 'two_factor':
          cancelPendingLogin();
          pendingLogin = { kek: null, challenge: result.challenge, sso: result.org };
          return { kind: 'two_factor', challenge: result.challenge };
        case 'link_required':
          // Completed once the account owner signs in with their master password (see App).
          sessionStorage.setItem(SSO_LINK_KEY, JSON.stringify({ linkToken: result.linkToken, org: result.org, email: result.email }));
          return { kind: 'link', email: result.email, orgName: result.orgName };
        case 'provision':
          return { kind: 'provision', email: result.email, name: result.name, orgName: result.orgName, provisionToken: result.provisionToken, org: result.org };
      }
    },

    async ssoProvision(provisionToken, org, name, password) {
      const measured = measureMasterPassword(password);
      const { payload, keys: fresh } = await createAccount(password);
      await measured;
      const res = await api<LoginResponse>('POST', '/api/sso/provision', { ...payload, name, provisionToken, deviceName: deviceName() }, { auth: false });
      establish(res, fresh, org);
      await get().sync();
    },

    isTrustedDevice() {
      const p = get().profile;
      const entry = p ? deviceFor(p.email) : null;
      return !!entry && entry.status === 'trusted' && entry.userId === p?.id;
    },

    async trustThisDevice() {
      const k = requireKeys();
      const profile = get().profile!;
      const previous = deviceFor(profile.email);
      const deviceId = uuid();
      const { entry, privateKey } = await newDevice(profile, deviceId);
      wipe(privateKey);
      await api('POST', '/api/devices/trust', {
        id: deviceId,
        name: deviceLabel(),
        publicKey: entry.publicKey,
        protectedUserKey: sealUserKeyForDevice(entry.publicKey, k.userKey, profile.id, deviceId),
      });
      saveDevice({ ...entry, status: 'trusted', sso: get().sso ?? undefined });
      if (previous && previous.userId === profile.id) await api('DELETE', `/api/devices/${previous.deviceId}`).catch(() => undefined);
    },

    async forgetThisDevice() {
      const profile = get().profile;
      const entry = profile ? deviceFor(profile.email) : null;
      if (!entry) return;
      forgetDevice(entry.email);
      await api('DELETE', `/api/devices/${entry.deviceId}`).catch(() => undefined);
    },

    async requestDeviceApproval(adminOrgId) {
      const profile = get().profile;
      if (!profile) throw new Error('Not signed in');
      const deviceId = uuid();
      const { entry, privateKey } = await newDevice(profile, deviceId);
      wipe(privateKey);
      await api('POST', '/api/devices/request', { id: deviceId, name: deviceLabel(), publicKey: entry.publicKey, adminOrgId });
      saveDevice({ ...entry, sso: get().sso ?? undefined });
      return { deviceId, fingerprint: fingerprint(fromB64(entry.publicKey)) };
    },

    async checkDeviceApproval() {
      const { profile, bundle } = get();
      const entry = profile ? deviceFor(profile.email) : null;
      if (!profile || !bundle || !entry || entry.status !== 'pending') return 'denied';
      let device: TrustedDevice;
      try {
        device = await api<TrustedDevice>('GET', `/api/devices/${entry.deviceId}`);
      } catch {
        return 'denied';
      }
      if (device.status === 'denied') return 'denied';
      if (!device.protectedUserKey) return 'pending';
      const privateKey = await unwrapDeviceKey(entry);
      try {
        keys = unlockWithUserKey(openDeviceUserKey(privateKey, device.protectedUserKey, profile.id, entry.deviceId), bundle);
      } finally {
        wipe(privateKey);
      }
      saveDevice({ ...entry, status: 'trusted' });
      set({ status: 'unlocked' });
      await get().sync();
      return 'approved';
    },

    rememberSso(org) {
      const p = readPersisted();
      if (p) writePersisted({ ...p, sso: org });
      set({ sso: org });
    },

    async approveDevice(device) {
      const k = requireKeys();
      const profile = get().profile!;
      await api('POST', `/api/devices/${device.id}/approve`, {
        protectedUserKey: sealUserKeyForDevice(device.publicKey, k.userKey, profile.id, device.id),
      });
    },
  };
});
