import { app, BrowserWindow, dialog, ipcMain, Menu, net, powerMonitor, protocol, session, shell } from 'electron';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { extname, join, normalize, sep } from 'node:path';
import { SETUP_CSS, SETUP_HTML, SETUP_JS } from './setup';

/**
 * Enclavier for Windows.
 *
 * The app is a locked-down shell around the same web vault that runs in the
 * browser. The vault's files ship inside the app and are served from a
 * private origin (app://vault), so nothing executable is ever downloaded from
 * the server. Only `/api` calls go over the network, to the server the user
 * chose, and they are made by this process (no CORS, no cookies).
 */

const ORIGIN = 'app://vault';
const WEB_ROOT = join(__dirname, 'web');

// Must happen before the app is ready: a standard, secure scheme gets
// localStorage, IndexedDB, WebCrypto and fetch like an https origin.
protocol.registerSchemesAsPrivileged([{ scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true, stream: true, codeCache: true } }]);

// ---- settings ---------------------------------------------------------------------------

interface Settings {
  serverUrl: string | null;
  /** Hide the window from screenshots, screen sharing and recordings. */
  blockCapture: boolean;
}

const settingsFile = () => join(app.getPath('userData'), 'settings.json');
let settings: Settings = { serverUrl: null, blockCapture: false };

function loadSettings() {
  try {
    settings = { ...settings, ...(JSON.parse(readFileSync(settingsFile(), 'utf8')) as Partial<Settings>) };
  } catch {
    // first run
  }
}

function saveSettings() {
  mkdirSync(app.getPath('userData'), { recursive: true });
  writeFileSync(settingsFile(), JSON.stringify(settings, null, 2));
}

/** https everywhere; plain http only for a server on this same machine. */
function normaliseServerUrl(input: string): string {
  const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input.trim()) ? input.trim() : `https://${input.trim()}`);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new Error('Use an https:// address (http is allowed only for localhost).');
  return url.origin;
}

async function probeServer(serverUrl: string): Promise<{ version: string }> {
  let res: Response;
  try {
    res = await net.fetch(`${serverUrl}/api/server-info`, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
  } catch {
    throw new Error(`Cannot reach ${serverUrl}. Check the address and your network.`);
  }
  const info = res.ok ? ((await res.json().catch(() => null)) as { name?: string; version?: string } | null) : null;
  if (info?.name !== 'Enclavier') throw new Error(`${serverUrl} is not an Enclavier server (or it runs a version older than this app supports).`);
  return { version: info.version ?? 'unknown' };
}

// ---- app:// protocol: bundled vault files + API proxy ------------------------------------------

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.wasm': 'application/wasm',
  '.woff2': 'font/woff2',
};

// Same policy as the hosted web vault: only the app's own code can run next to decrypted secrets.
const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

const respond = (body: string | Buffer, type: string, status = 200) =>
  new Response(body as BodyInit, { status, headers: { 'content-type': type, ...SECURITY_HEADERS } });

function serveFile(pathname: string): Response {
  // Resolve inside WEB_ROOT only; anything else falls back to the single-page app.
  const wanted = normalize(join(WEB_ROOT, decodeURIComponent(pathname)));
  const inside = wanted === WEB_ROOT || wanted.startsWith(WEB_ROOT + sep);
  const isAsset = inside && extname(wanted) !== '' && existsSync(wanted);
  if (!isAsset && pathname.startsWith('/assets/')) return respond('Not found', 'text/plain', 404);
  const file = isAsset ? wanted : join(WEB_ROOT, 'index.html');
  return respond(readFileSync(file), MIME[extname(file)] ?? 'application/octet-stream');
}

async function proxyApi(request: Request, url: URL): Promise<Response> {
  if (!settings.serverUrl) return respond(JSON.stringify({ error: 'not_configured', message: 'No server configured' }), 'application/json', 503);
  // Forward only what the API needs: no cookies, no ambient credentials.
  const headers: Record<string, string> = { 'user-agent': `Enclavier-Desktop/${app.getVersion()} (${process.platform})` };
  for (const name of ['content-type', 'authorization', 'accept']) {
    const v = request.headers.get(name);
    if (v) headers[name] = v;
  }
  const hasBody = !['GET', 'HEAD'].includes(request.method);
  let res: Response;
  try {
    res = await net.fetch(`${settings.serverUrl}${url.pathname}${url.search}`, {
      method: request.method,
      headers,
      body: hasBody ? await request.arrayBuffer() : undefined,
      redirect: 'manual',
      credentials: 'omit',
    });
  } catch {
    return respond(JSON.stringify({ error: 'network', message: `Cannot reach ${settings.serverUrl}` }), 'application/json', 502);
  }
  const out = new Headers({ 'cache-control': 'no-store' });
  for (const name of ['content-type', 'retry-after']) {
    const v = res.headers.get(name);
    if (v) out.set(name, v);
  }
  return new Response(res.status === 204 || res.status === 304 ? null : res.body, { status: res.status, headers: out });
}

function registerProtocol() {
  protocol.handle('app', async (request) => {
    const url = new URL(request.url);
    if (url.host !== 'vault') return respond('Not found', 'text/plain', 404);
    if (url.pathname === '/__setup') return respond(SETUP_HTML, MIME['.html']!);
    if (url.pathname === '/__setup.js') return respond(SETUP_JS, MIME['.js']!);
    if (url.pathname === '/__setup.css') return respond(SETUP_CSS, MIME['.css']!);
    if (url.pathname.startsWith('/api/') || url.pathname === '/health') return proxyApi(request, url);
    return serveFile(url.pathname);
  });
}

// ---- window ------------------------------------------------------------------------------

let win: BrowserWindow | null = null;
const startPage = () => (settings.serverUrl ? `${ORIGIN}/` : `${ORIGIN}/__setup`);

function lockVault() {
  void win?.webContents.executeJavaScript("window.dispatchEvent(new Event('enclavier:lock'))").catch(() => undefined);
}

/**
 * Single sign-on happens at the organization's identity provider, in a
 * separate, throwaway window with no access to the vault. When the provider
 * sends the browser back to the server's /sso/callback, the one-time code is
 * handed to the vault window.
 */
function openSsoWindow(target: string) {
  if (!win) return;
  const sso = new BrowserWindow({
    parent: win,
    modal: true,
    width: 520,
    height: 720,
    title: 'Sign in with your organization',
    autoHideMenuBar: true,
    webPreferences: { partition: `sso-${Date.now()}`, sandbox: true, contextIsolation: true, nodeIntegration: false },
  });
  sso.setMenu(null);
  const finish = (raw: string): boolean => {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return false;
    }
    if (url.pathname !== '/sso/callback' || !settings.serverUrl || url.hostname !== new URL(settings.serverUrl).hostname) return false;
    void win?.loadURL(`${ORIGIN}/sso/callback${url.hash}`);
    setImmediate(() => !sso.isDestroyed() && sso.close());
    return true;
  };
  sso.webContents.on('will-redirect', (e, url) => finish(url) && e.preventDefault());
  sso.webContents.on('will-navigate', (e, url) => finish(url) && e.preventDefault());
  sso.webContents.on('did-navigate', (_e, url) => void finish(url));
  sso.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  void sso.loadURL(target);
}

function createWindow() {
  win = new BrowserWindow({
    width: 1240,
    height: 820,
    minWidth: 420,
    minHeight: 560,
    show: false,
    backgroundColor: '#f8fafc',
    title: 'Enclavier',
    icon: join(__dirname, 'icon.png'),
    autoHideMenuBar: true,
    webPreferences: {
      preload: join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      spellcheck: false, // never send vault text to a spelling service
      devTools: !app.isPackaged,
    },
  });
  win.setContentProtection(settings.blockCapture);
  win.once('ready-to-show', () => win?.show());
  win.on('closed', () => (win = null));

  // The vault window only ever shows the bundled app.
  win.webContents.on('will-navigate', (e, url) => {
    if (url.startsWith(`${ORIGIN}/`)) return;
    e.preventDefault();
    // The web vault starts SSO by navigating to the identity provider.
    if (/^https:\/\//i.test(url) || (/^http:\/\//i.test(url) && settings.serverUrl?.startsWith('http://'))) openSsoWindow(url);
  });
  // "Launch" buttons and other links open in the user's default browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) void shell.openExternal(url);
    return { action: 'deny' };
  });
  void win.loadURL(startPage());
}

async function changeServer() {
  if (!win) return;
  const { response } = await dialog.showMessageBox(win, {
    type: 'question',
    buttons: ['Change server', 'Cancel'],
    defaultId: 1,
    cancelId: 1,
    message: 'Connect to a different Enclavier server?',
    detail: 'You will be signed out on this computer. Nothing is deleted from the server.',
  });
  if (response !== 0) return;
  await session.defaultSession.clearStorageData();
  settings.serverUrl = null;
  saveSettings();
  await win.loadURL(startPage());
}

function buildMenu() {
  Menu.setApplicationMenu(
    Menu.buildFromTemplate([
      {
        label: '&File',
        submenu: [
          { label: 'Lock vault', accelerator: 'Ctrl+L', click: lockVault },
          { type: 'separator' },
          { label: 'Change server…', click: () => void changeServer() },
          { type: 'separator' },
          { role: 'quit', label: 'Exit' },
        ],
      },
      { label: '&Edit', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
      {
        label: '&View',
        submenu: [
          { role: 'reload' },
          { type: 'separator' },
          { role: 'resetZoom' },
          { role: 'zoomIn' },
          { role: 'zoomOut' },
          { type: 'separator' },
          { role: 'togglefullscreen' },
          { type: 'separator' },
          {
            label: 'Block screen capture',
            type: 'checkbox',
            checked: settings.blockCapture,
            click: (item) => {
              settings.blockCapture = item.checked;
              saveSettings();
              win?.setContentProtection(item.checked);
            },
          },
        ],
      },
      {
        label: '&Help',
        submenu: [
          {
            label: 'About Enclavier',
            click: () =>
              win &&
              void dialog.showMessageBox(win, {
                type: 'info',
                message: `Enclavier ${app.getVersion()}`,
                detail: `Server: ${settings.serverUrl ?? 'not connected'}\n\nYour vault is encrypted on this computer. The server never sees your master password or what you store.\n\nOpen source under AGPL-3.0.`,
              }),
          },
        ],
      },
    ]),
  );
}

// ---- lifecycle ----------------------------------------------------------------------------

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (!win) return;
    if (win.isMinimized()) win.restore();
    win.focus();
  });

  void app.whenReady().then(() => {
    loadSettings();
    registerProtocol();

    // Pages get no device permissions except writing to the clipboard (copy buttons).
    session.defaultSession.setPermissionRequestHandler((wc, permission, callback) => {
      callback(permission === 'clipboard-sanitized-write' && wc.getURL().startsWith(`${ORIGIN}/`));
    });
    session.defaultSession.setPermissionCheckHandler((_wc, permission, origin) => permission === 'clipboard-sanitized-write' && origin.startsWith(ORIGIN));

    // Setup page: choose (and verify) the server.
    ipcMain.handle('enclavier:connect', async (event, input: unknown) => {
      if (!event.senderFrame?.url.startsWith(`${ORIGIN}/__setup`)) throw new Error('Not allowed');
      const serverUrl = normaliseServerUrl(String(input ?? ''));
      await probeServer(serverUrl);
      settings.serverUrl = serverUrl;
      saveSettings();
      setImmediate(() => void win?.loadURL(startPage()));
      return serverUrl;
    });

    // Lock when Windows locks or goes to sleep.
    powerMonitor.on('lock-screen', lockVault);
    powerMonitor.on('suspend', lockVault);

    buildMenu();
    createWindow();
  });

  app.on('window-all-closed', () => app.quit());
  // No new windows or webviews beyond the ones created above.
  app.on('web-contents-created', (_e, contents) => {
    contents.on('will-attach-webview', (e) => e.preventDefault());
  });
}
