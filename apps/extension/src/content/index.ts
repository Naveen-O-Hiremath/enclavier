import type { ContentCommand, Request } from '../shared/messages';

// Runs in every page (isolated world). It never sees the vault: it only
// receives values to fill for this page's own origin, reports submitted
// credentials, and hosts the inline menu, which is an extension-origin iframe
// the page can't read.

declare global {
  interface Window {
    __enclavier?: boolean;
  }
}

if (!window.__enclavier) {
  window.__enclavier = true;
  main();
}

function main() {
  const send = (req: Request) => chrome.runtime.sendMessage(req).catch(() => undefined);

  // ---- field detection ----------------------------------------------------------------------

  const USER_HINT = /user|email|e-mail|login|account|ident|mail/i;
  const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|auth.?code|security.?code/i;

  function visible(el: HTMLElement): boolean {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.hasAttribute('disabled');
  }

  const inputs = (root: ParentNode = document) => [...root.querySelectorAll<HTMLInputElement>('input')].filter((i) => visible(i) && !i.readOnly);
  const passwordFields = (root: ParentNode = document) => inputs(root).filter((i) => i.type === 'password');

  function isUsernameField(i: HTMLInputElement): boolean {
    if (!['text', 'email', 'tel', ''].includes(i.type)) return false;
    const ac = (i.autocomplete || '').toLowerCase();
    if (ac.includes('username') || ac === 'email') return true;
    return USER_HINT.test(`${i.name} ${i.id} ${i.placeholder} ${i.getAttribute('aria-label') ?? ''}`);
  }

  /** The text field just before the password in document order, preferring obvious username fields. */
  function usernameFor(password: HTMLInputElement | undefined): HTMLInputElement | undefined {
    const scope = password?.form ?? document;
    const candidates = inputs(scope).filter((i) => ['text', 'email', 'tel', ''].includes(i.type));
    if (!password) return candidates.find(isUsernameField);
    const before = candidates.filter((i) => i.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING);
    return [...before].reverse().find(isUsernameField) ?? before[before.length - 1];
  }

  function otpField(): HTMLInputElement | undefined {
    return inputs().find(
      (i) => i.autocomplete === 'one-time-code' || (['text', 'tel', 'number', ''].includes(i.type) && OTP_HINT.test(`${i.name} ${i.id} ${i.placeholder} ${i.getAttribute('aria-label') ?? ''}`)),
    );
  }

  // React/Vue/Angular track values through the native setter: use it, then fire the events they listen for.
  function setValue(el: HTMLInputElement, value: string) {
    el.focus();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    if (setter) setter.call(el, value);
    else el.value = value;
    for (const type of ['input', 'change']) el.dispatchEvent(new Event(type, { bubbles: true }));
    el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
    el.blur();
  }

  function fill(cmd: Extract<ContentCommand, { type: 'fill' }>) {
    // Only frames on the page's own origin: never a third-party iframe.
    if (location.origin !== cmd.expectOrigin) return;
    const pw = passwordFields()[0];
    const user = usernameFor(pw);
    let filled = false;
    if (user && cmd.username) {
      setValue(user, cmd.username);
      filled = true;
    }
    if (pw && cmd.password) {
      setValue(pw, cmd.password);
      filled = true;
    }
    if (!pw && cmd.totp) {
      const otp = otpField();
      if (otp) {
        setValue(otp, cmd.totp);
        filled = true;
      }
    }
    if (filled) closeInline();
  }

  // ---- inline icon + menu ---------------------------------------------------------------------

  let host: HTMLElement | null = null;
  let shadow: ShadowRoot | null = null;
  let anchor: HTMLInputElement | null = null;
  let menu: HTMLIFrameElement | null = null;

  function ensureHost(): ShadowRoot {
    if (shadow && host?.isConnected) return shadow;
    host = document.createElement('enclavier-ui');
    host.style.cssText = 'all: initial; position: absolute; top: 0; left: 0; z-index: 2147483647;';
    shadow = host.attachShadow({ mode: 'closed' });
    document.documentElement.appendChild(host);
    return shadow;
  }

  // The Enclavier logo, loaded from the extension itself (listed in web_accessible_resources).
  function logo(size: number): HTMLImageElement {
    const img = document.createElement('img');
    img.src = chrome.runtime.getURL('icons/32.png');
    img.alt = '';
    img.width = size;
    img.height = size;
    img.style.cssText = `width:${size}px;height:${size}px;border-radius:22%;display:block;pointer-events:none;`;
    return img;
  }

  let icon: HTMLButtonElement | null = null;

  function placeIcon(field: HTMLInputElement) {
    const root = ensureHost();
    if (!icon) {
      icon = document.createElement('button');
      icon.title = 'Enclavier: fill a login';
      icon.appendChild(logo(18));
      icon.style.cssText =
        'position:absolute;width:22px;height:22px;padding:2px;border:0;border-radius:6px;background:#0a1630;cursor:pointer;display:flex;align-items:center;justify-content:center;box-shadow:0 1px 2px rgba(0,0,0,.15);';
      icon.addEventListener('mousedown', (e) => e.preventDefault()); // keep focus in the field
      icon.addEventListener('click', (e) => {
        if (!e.isTrusted) return;
        void openMenu();
      });
      root.appendChild(icon);
    }
    anchor = field;
    const r = field.getBoundingClientRect();
    icon.style.top = `${r.top + window.scrollY + (r.height - 22) / 2}px`;
    icon.style.left = `${r.right + window.scrollX - 26}px`;
    icon.style.display = 'flex';
  }

  function hideIcon() {
    if (icon) icon.style.display = 'none';
  }

  async function openMenu() {
    if (!anchor) return;
    const res = (await send({ type: 'openInline', frameRect: { top: 0, left: 0, width: 0, height: 0 } })) as { ok: boolean; data?: { available: boolean } } | undefined;
    if (!res?.ok) return;
    const root = ensureHost();
    closeInline();
    menu = document.createElement('iframe');
    menu.src = chrome.runtime.getURL('inline.html');
    const r = anchor.getBoundingClientRect();
    menu.style.cssText = `position:absolute;top:${r.bottom + window.scrollY + 4}px;left:${Math.max(4, r.left + window.scrollX)}px;width:320px;height:240px;border:0;border-radius:10px;box-shadow:0 10px 30px rgba(15,23,42,.25);background:#fff;color-scheme:light dark;`;
    menu.setAttribute('allow', 'clipboard-write');
    root.appendChild(menu);
  }

  function closeInline() {
    menu?.remove();
    menu = null;
  }

  document.addEventListener(
    'focusin',
    (e) => {
      const t = e.target;
      if (!(t instanceof HTMLInputElement)) return;
      const loginContext = t.type === 'password' || (isUsernameField(t) && (passwordFields().length > 0 || t.autocomplete.includes('username')));
      if (loginContext && visible(t)) placeIcon(t);
      else hideIcon();
    },
    true,
  );
  document.addEventListener('keydown', (e) => e.key === 'Escape' && closeInline(), true);
  document.addEventListener(
    'mousedown',
    (e) => {
      if (menu && e.target !== host) closeInline();
    },
    true,
  );
  window.addEventListener('scroll', () => anchor && icon?.style.display !== 'none' && placeIcon(anchor), { passive: true });

  // ---- save-on-submit ---------------------------------------------------------------------------

  let lastReport = '';
  function report(scope: ParentNode) {
    const pw = passwordFields(scope).find((p) => p.value) ?? passwordFields().find((p) => p.value);
    if (!pw) return;
    const user = usernameFor(pw)?.value.trim() ?? '';
    const key = `${user}\u0000${pw.value}`;
    if (key === lastReport) return;
    lastReport = key;
    void send({ type: 'formSubmitted', url: location.href, username: user, password: pw.value });
  }

  document.addEventListener('submit', (e) => e.target instanceof HTMLFormElement && report(e.target), true);
  // Many sign-in pages don't submit a form: they POST with fetch when a button is clicked or Enter is pressed.
  document.addEventListener(
    'click',
    (e) => {
      const b = (e.target as Element | null)?.closest?.('button, input[type=submit], [role=button]');
      if (b && passwordFields().some((p) => p.value)) report((b as HTMLElement).closest('form') ?? document);
    },
    true,
  );
  document.addEventListener(
    'keydown',
    (e) => {
      if (e.key === 'Enter' && e.target instanceof HTMLInputElement && (e.target.type === 'password' || passwordFields().some((p) => p.value))) {
        report(e.target.form ?? document);
      }
    },
    true,
  );

  let bar: HTMLElement | null = null;
  function showSaveBar(cmd: Extract<ContentCommand, { type: 'showSaveBar' }>) {
    if (window.top !== window) return;
    bar?.remove();
    const root = ensureHost();
    bar = document.createElement('div');
    bar.style.cssText =
      'position:fixed;top:16px;right:16px;width:340px;padding:14px 16px;border-radius:12px;background:#fff;color:#0f172a;font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;box-shadow:0 12px 32px rgba(15,23,42,.25);border:1px solid #e2e8f0;';
    const title = document.createElement('div');
    title.style.cssText = 'display:flex;align-items:center;gap:8px;font-weight:600;';
    title.appendChild(logo(20));
    title.append(cmd.mode === 'update' ? 'Update password in Enclavier?' : 'Save this login to Enclavier?');
    const detail = document.createElement('div');
    detail.style.cssText = 'margin:6px 0 12px;color:#475569;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
    detail.textContent = `${cmd.username || '(no username)'} · ${cmd.host}`;
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;';
    const button = (label: string, primary: boolean, decision: 'save' | 'update' | 'never' | 'dismiss') => {
      const b = document.createElement('button');
      b.textContent = label;
      b.style.cssText = `padding:6px 12px;border-radius:8px;font:500 13px system-ui,sans-serif;cursor:pointer;border:1px solid ${primary ? '#4f46e5' : '#cbd5e1'};background:${primary ? '#4f46e5' : '#fff'};color:${primary ? '#fff' : '#334155'};`;
      b.addEventListener('click', (e) => {
        if (!e.isTrusted) return; // the page can't click "Save" for the user
        void send({ type: 'savePrompt', decision });
        bar?.remove();
        bar = null;
      });
      return b;
    };
    row.append(button('Never for this site', false, 'never'), button('Not now', false, 'dismiss'), button(cmd.mode === 'update' ? 'Update' : 'Save', true, cmd.mode));
    bar.append(title, detail, row);
    root.appendChild(bar);
    setTimeout(() => {
      bar?.remove();
      bar = null;
    }, 30_000);
  }

  // ---- commands from the background ------------------------------------------------------------------

  chrome.runtime.onMessage.addListener((cmd: ContentCommand, sender) => {
    if (sender.id !== chrome.runtime.id) return;
    if (cmd.type === 'fill') fill(cmd);
    else if (cmd.type === 'showSaveBar') showSaveBar(cmd);
    else if (cmd.type === 'closeInline') closeInline();
  });
}

export {};
