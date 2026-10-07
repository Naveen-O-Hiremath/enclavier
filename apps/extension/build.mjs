// Builds dist/chrome (Chrome, Edge, Brave, Opera) and dist/firefox from one source tree.
import { build as esbuild } from 'esbuild';
import { build as vite } from 'vite';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, 'dist');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

rmSync(dist, { recursive: true, force: true });

// 1. Extension pages (React + Tailwind).
await vite({ configFile: join(root, 'vite.config.ts'), root, logLevel: 'warn' });

// 2. Background (module service worker / event page) and content script (classic script).
const common = { bundle: true, minify: true, legalComments: 'none', target: ['chrome116', 'firefox115'], define: { 'process.env.NODE_ENV': '"production"' } };
await esbuild({ ...common, entryPoints: [join(root, 'src/background/index.ts')], outfile: join(dist, '.scripts/background.js'), format: 'esm', platform: 'browser' });
await esbuild({ ...common, entryPoints: [join(root, 'src/content/index.ts')], outfile: join(dist, '.scripts/content.js'), format: 'iife', platform: 'browser' });

// 3. Icons: pre-rendered from the logo by assets/brand/generate.py.
const brand = join(root, '..', '..', 'assets', 'brand');
const icons = { 16: 'icons/16.png', 32: 'icons/32.png', 48: 'icons/48.png', 128: 'icons/128.png' };

// 4. Manifests.
const base = {
  manifest_version: 3,
  name: 'Enclavier',
  short_name: 'Enclavier',
  version: pkg.version,
  description: 'Zero-knowledge password manager: autofill, save logins and generate passwords from your Enclavier vault.',
  icons,
  action: { default_popup: 'popup.html', default_title: 'Enclavier', default_icon: icons },
  permissions: ['storage', 'tabs', 'alarms', 'idle', 'clipboardWrite'],
  optional_host_permissions: ['https://*/*', 'http://localhost/*', 'http://127.0.0.1/*'],
  content_scripts: [{ matches: ['http://*/*', 'https://*/*'], js: ['content.js'], all_frames: true, run_at: 'document_idle' }],
  web_accessible_resources: [{ resources: ['inline.html', 'assets/*', 'icons/32.png', 'icons/128.png'], matches: ['http://*/*', 'https://*/*'] }],
  commands: {
    _execute_action: { suggested_key: { default: 'Ctrl+Shift+Y', mac: 'Command+Shift+Y' } },
    autofill: { suggested_key: { default: 'Ctrl+Shift+L', mac: 'Command+Shift+L' }, description: 'Fill the best matching login on this page' },
  },
  content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'" },
};

const targets = {
  chrome: {
    ...base,
    permissions: [...base.permissions, 'offscreen'],
    background: { service_worker: 'background.js', type: 'module' },
    minimum_chrome_version: '116',
  },
  firefox: {
    ...base,
    background: { scripts: ['background.js'], type: 'module' },
    browser_specific_settings: { gecko: { id: 'extension@enclavier.codearrive.in', strict_min_version: '115.0' } },
  },
};

for (const [name, manifest] of Object.entries(targets)) {
  const out = join(dist, name);
  mkdirSync(join(out, 'icons'), { recursive: true });
  cpSync(join(dist, '.pages'), out, { recursive: true });
  cpSync(join(dist, '.scripts'), out, { recursive: true });
  for (const [size, file] of Object.entries(icons)) cpSync(join(brand, `icon-${size}.png`), join(out, file));
  if (name === 'firefox') rmSync(join(out, 'offscreen.html'), { force: true });
  writeFileSync(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2));
}
rmSync(join(dist, '.pages'), { recursive: true, force: true });
rmSync(join(dist, '.scripts'), { recursive: true, force: true });
console.log('Built dist/chrome and dist/firefox');
