import { generatePassword, InvalidPasswordError, parseTotp, totpCode } from '@enclavier/crypto';
import type { ContentCommand, ItemSummary, Request, Response } from '../shared/messages';
import { hostOf, matchScore, originOf, uriMatches } from './match';
import {
  allEntries,
  cancelTwoFactor,
  clipboardSeconds,
  completeTwoFactor,
  effectiveLockMinutes,
  ensureLoaded,
  findEntry,
  isUnlocked,
  lock,
  login,
  logout,
  orgName,
  saveLogin,
  serverUrl,
  setLockMinutes,
  state,
  sync,
  unlock,
  updatePassword,
  type VaultEntry,
} from './vault';

const LOCK_ALARM = 'enclavier-autolock';
const NEVER_KEY = 'enclavier.neverSave';

// ---- helpers ------------------------------------------------------------------------------------

function uris(e: VaultEntry): string[] {
  return e.data.type === 'login' ? (e.data.login?.uris ?? []) : [];
}

function score(e: VaultEntry, pageUrl: string | undefined): number {
  if (!pageUrl) return 0;
  return Math.max(0, ...uris(e).map((u) => matchScore(u, pageUrl)));
}

function summary(e: VaultEntry, pageUrl?: string): ItemSummary {
  const d = e.data;
  return {
    id: e.id,
    name: d.name,
    type: d.type,
    username: d.login?.username ?? d.identity?.email ?? (d.card?.number ? `•••• ${d.card.number.slice(-4)}` : ''),
    uri: uris(e)[0] ?? null,
    hasPassword: !!d.login?.password,
    hasTotp: !!d.login?.totp,
    favorite: !!d.favorite,
    org: orgName(e.orgId),
    permission: e.permission,
    match: score(e, pageUrl) > 0,
  };
}

/** Logins for this page, best match first. */
function matchesFor(pageUrl: string | undefined): VaultEntry[] {
  if (!pageUrl) return [];
  return allEntries()
    .filter((e) => score(e, pageUrl) > 0)
    .sort((a, b) => score(b, pageUrl) - score(a, pageUrl) || Number(!!b.data.favorite) - Number(!!a.data.favorite) || a.data.name.localeCompare(b.data.name));
}

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab;
}

function totpFor(e: VaultEntry): string | null {
  const secret = e.data.login?.totp;
  if (!secret) return null;
  try {
    return totpCode(parseTotp(secret)).code;
  } catch {
    return null;
  }
}

async function sendToTab(tabId: number, cmd: ContentCommand, frameId?: number) {
  try {
    await chrome.tabs.sendMessage(tabId, cmd, frameId === undefined ? undefined : { frameId });
  } catch {
    // no content script on this page (browser pages, store pages…)
  }
}

/**
 * Autofill is only ever sent to a tab whose address matches the item, and the
 * content script additionally fills only frames on the page's own origin.
 */
async function fill(e: VaultEntry, tab: chrome.tabs.Tab | undefined) {
  if (!tab?.id || !tab.url) throw new Error('No page to fill');
  if (e.data.type !== 'login') throw new Error('Only logins can be autofilled');
  if (!uris(e).some((u) => uriMatches(u, tab.url!))) {
    throw new Error(`This login is saved for ${uris(e).map(hostOf).join(', ') || 'no website'}, not ${hostOf(tab.url)}. Copy it instead if you're sure.`);
  }
  const origin = originOf(tab.url)!;
  await sendToTab(tab.id, {
    type: 'fill',
    username: e.data.login?.username ?? '',
    password: e.data.login?.password ?? '',
    totp: totpFor(e),
    expectOrigin: origin,
  });
  touch();
}

// ---- auto-lock ------------------------------------------------------------------------------------

async function touch() {
  const s = await state();
  if (s.status !== 'unlocked') return;
  const minutes = effectiveLockMinutes(s.lockMinutes);
  if (minutes > 0) await chrome.alarms.create(LOCK_ALARM, { delayInMinutes: minutes });
  else await chrome.alarms.clear(LOCK_ALARM);
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === LOCK_ALARM) void lock().then(updateBadge);
  if (alarm.name === 'enclavier-clipboard') void clearClipboard();
});

// Lock when the computer is locked.
chrome.idle?.onStateChanged.addListener((s) => {
  if (s === 'locked') void lock().then(updateBadge);
});

// ---- clipboard clearing (popup windows close before a timer could fire) --------------------------------

async function clearClipboard() {
  if (typeof document !== 'undefined') {
    // Firefox: the background is an event page with a DOM.
    const t = document.createElement('textarea');
    t.value = ' ';
    document.body.appendChild(t);
    t.select();
    document.execCommand('copy');
    t.remove();
    return;
  }
  // Chrome: service workers have no DOM; use an offscreen document.
  const offscreen = chrome.offscreen;
  if (!offscreen) return;
  if (!(await offscreen.hasDocument?.())) {
    await offscreen.createDocument({ url: 'offscreen.html', reasons: [offscreen.Reason.CLIPBOARD], justification: 'Clear copied passwords from the clipboard' });
  }
  await chrome.runtime.sendMessage({ type: 'offscreen-clear-clipboard' });
}

// ---- save-on-submit -------------------------------------------------------------------------------

interface PendingSave {
  url: string;
  username: string;
  password: string;
  updateId: string | null;
  at: number;
}
const pendingSaves = new Map<number, PendingSave>();

async function neverSaveHosts(): Promise<string[]> {
  return ((await chrome.storage.local.get(NEVER_KEY))[NEVER_KEY] as string[] | undefined) ?? [];
}

async function offerSave(tabId: number, p: PendingSave) {
  await sendToTab(tabId, { type: 'showSaveBar', mode: p.updateId ? 'update' : 'save', host: hostOf(p.url), username: p.username }, 0);
}

async function onSubmitted(tabId: number, url: string, username: string, password: string) {
  if (!isUnlocked() || !password || !originOf(url)) return;
  if ((await neverSaveHosts()).includes(hostOf(url))) return;
  const sameUser = matchesFor(url).filter((e) => (e.data.login?.username ?? '').toLowerCase() === username.toLowerCase());
  if (sameUser.some((e) => e.data.login?.password === password)) return; // already saved
  const updatable = sameUser.find((e) => e.permission === 'edit' || e.permission === 'manage');
  if (sameUser.length && !updatable) return; // shared item the user can't change
  const p: PendingSave = { url, username, password, updateId: updatable?.id ?? null, at: Date.now() };
  pendingSaves.set(tabId, p);
  await offerSave(tabId, p); // single-page apps: the page is still there
}

// After a submit usually comes a navigation: ask again on the next page.
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status !== 'complete') return;
  const p = pendingSaves.get(tabId);
  if (p && Date.now() - p.at < 2 * 60_000) void offerSave(tabId, p);
  else pendingSaves.delete(tabId);
  const launch = pendingLaunches.get(tabId);
  if (launch && tab.url) {
    const e = findEntry(launch.id);
    if (e && Date.now() - launch.at < 60_000 && uris(e).some((u) => uriMatches(u, tab.url!))) {
      pendingLaunches.delete(tabId);
      void fill(e, tab).catch(() => undefined);
    }
  }
  void updateBadge();
});
chrome.tabs.onRemoved.addListener((tabId) => {
  pendingSaves.delete(tabId);
  pendingLaunches.delete(tabId);
});
chrome.tabs.onActivated.addListener(() => void updateBadge());

// ---- launch & fill -------------------------------------------------------------------------------

const pendingLaunches = new Map<number, { id: string; at: number }>();

// ---- badge ---------------------------------------------------------------------------------------

async function updateBadge() {
  const tab = await activeTab().catch(() => undefined);
  const n = isUnlocked() && tab?.url ? matchesFor(tab.url).length : 0;
  await chrome.action.setBadgeText({ text: n ? String(n) : '' }).catch(() => undefined);
  await chrome.action.setBadgeBackgroundColor({ color: '#4f46e5' }).catch(() => undefined);
}

// ---- keyboard shortcut ---------------------------------------------------------------------------

chrome.commands.onCommand.addListener((command) => {
  if (command !== 'autofill') return;
  void (async () => {
    await ensureLoaded();
    const tab = await activeTab();
    const best = matchesFor(tab?.url)[0];
    if (isUnlocked() && best) await fill(best, tab);
    else await chrome.action.openPopup?.().catch(() => undefined);
  })();
});

// ---- message router ------------------------------------------------------------------------------

async function handle(req: Request, sender: chrome.runtime.MessageSender): Promise<unknown> {
  await ensureLoaded();
  // Classify by origin: extension pages (popup, picker) are served from our own origin; content scripts report the web page's URL.
  const ours = sender.id === chrome.runtime.id && !!sender.url?.startsWith(chrome.runtime.getURL(''));
  const fromInline = ours && !!sender.tab && sender.url!.startsWith(chrome.runtime.getURL('inline.html'));
  const fromExtensionPage = ours && !fromInline; // popup (as a popup or opened in a tab)
  const fromContent = sender.id === chrome.runtime.id && !ours && !!sender.tab;

  // Content scripts run inside web pages: they may only report submits, ask for the inline menu and relay prompt decisions.
  if (fromContent && !['formSubmitted', 'savePrompt', 'openInline', 'activity'].includes(req.type)) {
    throw new Error('Not allowed');
  }
  if (fromInline && !['inlineItems', 'inlineFill', 'inlineClose', 'state'].includes(req.type)) throw new Error('Not allowed');
  if (!fromExtensionPage && !fromInline && !fromContent) throw new Error('Not allowed');

  switch (req.type) {
    case 'state':
      return state();
    case 'login': {
      const result = await login(req.serverUrl, req.email.trim().toLowerCase(), req.password);
      if (result === 'unlocked') await touch();
      void updateBadge();
      return result;
    }
    case 'login2fa':
      await completeTwoFactor(req.method, req.code);
      await touch();
      void updateBadge();
      return null;
    case 'cancel2fa':
      cancelTwoFactor();
      return null;
    case 'unlock':
      try {
        await unlock(req.password);
      } catch (e) {
        if (e instanceof InvalidPasswordError) throw new Error('Incorrect master password');
        throw e;
      }
      await touch();
      void updateBadge();
      return null;
    case 'lock':
      await lock();
      void updateBadge();
      return null;
    case 'logout':
      await logout();
      void updateBadge();
      return null;
    case 'sync':
      await sync();
      void updateBadge();
      return null;
    case 'items': {
      const tab = req.tabId ? await chrome.tabs.get(req.tabId) : await activeTab();
      await touch();
      return allEntries()
        .map((e) => summary(e, tab?.url))
        .sort((a, b) => Number(b.match) - Number(a.match) || Number(b.favorite) - Number(a.favorite) || a.name.localeCompare(b.name));
    }
    case 'copy': {
      const e = findEntry(req.id);
      if (!e) throw new Error('Item not found');
      const secret = req.field === 'password' || req.field === 'cardNumber' || req.field === 'cardCode' || req.field === 'note';
      if (secret && e.permission === 'use') throw new Error('Your organization lets you autofill this item but not view or copy its secrets');
      const d = e.data;
      const value = {
        username: d.login?.username,
        password: d.login?.password,
        totp: totpFor(e),
        uri: uris(e)[0],
        cardNumber: d.card?.number,
        cardCode: d.card?.code,
        note: d.notes,
      }[req.field];
      if (!value) throw new Error('Nothing to copy');
      if (secret || req.field === 'totp') await chrome.alarms.create('enclavier-clipboard', { delayInMinutes: clipboardSeconds() / 60 });
      await touch();
      return value;
    }
    case 'fill': {
      const e = findEntry(req.id);
      if (!e) throw new Error('Item not found');
      await fill(e, req.tabId ? await chrome.tabs.get(req.tabId) : await activeTab());
      return null;
    }
    case 'launch': {
      const e = findEntry(req.id);
      const url = e ? uris(e).map((u) => originOf(u) && new URL(/^[a-z]+:\/\//i.test(u) ? u : `https://${u}`).href).find(Boolean) : null;
      if (!e || !url) throw new Error('This item has no website');
      const tab = await chrome.tabs.create({ url });
      if (tab.id) pendingLaunches.set(tab.id, { id: e.id, at: Date.now() });
      return null;
    }
    case 'generate':
      return generatePassword(req.options);
    case 'setLockMinutes':
      await setLockMinutes(req.minutes);
      await touch();
      return null;
    case 'openVault': {
      const url = await serverUrl();
      if (url) await chrome.tabs.create({ url: `${url}/vault` });
      return null;
    }
    case 'activity':
      if (isUnlocked()) await touch();
      return null;

    // ---- inline menu (extension-origin iframe inside the page) ----
    case 'inlineItems':
      if (!isUnlocked()) return { locked: true, items: [] };
      return { locked: false, items: matchesFor(sender.tab?.url).map((e) => summary(e, sender.tab?.url)) };
    case 'inlineFill': {
      const e = findEntry(req.id);
      if (!e || !sender.tab) throw new Error('Item not found');
      await fill(e, sender.tab);
      await sendToTab(sender.tab.id!, { type: 'closeInline' });
      return null;
    }
    case 'inlineClose':
      if (sender.tab?.id) await sendToTab(sender.tab.id, { type: 'closeInline' });
      return null;
    case 'openInline':
      if (!sender.tab?.id) return null;
      // The page asked; the menu itself is ours (a separate origin the page can't read).
      return { available: true, unlocked: isUnlocked(), count: isUnlocked() ? matchesFor(sender.tab.url).length : 0 };

    // ---- save-on-submit ----
    case 'formSubmitted':
      if (sender.tab?.id && sender.frameId === 0) await onSubmitted(sender.tab.id, sender.tab.url ?? req.url, req.username, req.password);
      else if (sender.tab?.id && sender.tab.url && originOf(req.url) === originOf(sender.tab.url)) await onSubmitted(sender.tab.id, sender.tab.url, req.username, req.password);
      return null;
    case 'savePrompt': {
      const tabId = sender.tab?.id;
      const p = tabId ? pendingSaves.get(tabId) : undefined;
      if (!tabId || !p) return null;
      pendingSaves.delete(tabId);
      if (req.decision === 'never') {
        await chrome.storage.local.set({ [NEVER_KEY]: [...new Set([...(await neverSaveHosts()), hostOf(p.url)])] });
      } else if (req.decision === 'update' && p.updateId) {
        await updatePassword(p.updateId, p.password);
      } else if (req.decision === 'save' && !p.updateId) {
        await saveLogin({ name: hostOf(p.url).replace(/^www\./, ''), uri: originOf(p.url)!, username: p.username, password: p.password });
      }
      void updateBadge();
      return null;
    }
  }
}

chrome.runtime.onMessage.addListener((req: Request, sender, sendResponse: (r: Response) => void) => {
  if ((req as { type?: string }).type === 'offscreen-clear-clipboard') return false;
  handle(req, sender).then(
    (data) => sendResponse({ ok: true, data }),
    (e: unknown) => sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) }),
  );
  return true; // async response
});

chrome.runtime.onInstalled.addListener(() => void updateBadge());
chrome.runtime.onStartup.addListener(() => void updateBadge());
