import type { PasswordOptions } from '@enclavier/crypto';
import type { Permission, TwoFactorMethod } from '@enclavier/shared';

export type Status = 'loggedOut' | 'locked' | 'unlocked';

export interface ExtState {
  status: Status;
  serverUrl: string | null;
  email: string | null;
  name: string | null;
  /** Second factor pending after the master password step. */
  twoFactor: { methods: TwoFactorMethod[]; webauthn: boolean } | null;
  /** Minutes of inactivity before the vault locks (0 = only when the browser closes). */
  lockMinutes: number;
}

/** What the popup and the inline menu may see about an item: never a secret. */
export interface ItemSummary {
  id: string;
  name: string;
  type: 'login' | 'note' | 'card' | 'identity';
  username: string;
  uri: string | null;
  hasPassword: boolean;
  hasTotp: boolean;
  favorite: boolean;
  org: string | null;
  permission: Permission;
  /** Matches the current page. */
  match: boolean;
}

export type CopyField = 'username' | 'password' | 'totp' | 'uri' | 'cardNumber' | 'cardCode' | 'note';

/** Popup / inline menu → background. */
export type Request =
  | { type: 'state' }
  | { type: 'login'; serverUrl: string; email: string; password: string }
  | { type: 'login2fa'; method: TwoFactorMethod; code: string }
  | { type: 'cancel2fa' }
  | { type: 'unlock'; password: string }
  | { type: 'lock' }
  | { type: 'logout' }
  | { type: 'sync' }
  | { type: 'items'; tabId?: number }
  | { type: 'copy'; id: string; field: CopyField }
  | { type: 'fill'; id: string; tabId?: number }
  | { type: 'launch'; id: string }
  | { type: 'generate'; options: PasswordOptions }
  | { type: 'setLockMinutes'; minutes: number }
  | { type: 'openVault' }
  // inline menu inside a page (extension-origin iframe)
  | { type: 'inlineItems' }
  | { type: 'inlineFill'; id: string }
  | { type: 'inlineClose' }
  // content script
  | { type: 'formSubmitted'; url: string; username: string; password: string }
  | { type: 'savePrompt'; decision: 'save' | 'update' | 'never' | 'dismiss' }
  | { type: 'openInline'; frameRect: { top: number; left: number; width: number; height: number } }
  | { type: 'activity' };

export type Response<T = unknown> = { ok: true; data: T } | { ok: false; error: string };

/** Background → content script. */
export type ContentCommand =
  | { type: 'fill'; username: string; password: string; totp: string | null; expectOrigin: string }
  | { type: 'showSaveBar'; mode: 'save' | 'update'; host: string; username: string }
  | { type: 'showInline'; open: boolean }
  | { type: 'closeInline' };

export async function send<T>(req: Request): Promise<T> {
  const res = (await chrome.runtime.sendMessage(req)) as Response<T> | undefined;
  if (!res) throw new Error('Enclavier is not responding. Try again.');
  if (!res.ok) throw new Error(res.error);
  return res.data;
}
