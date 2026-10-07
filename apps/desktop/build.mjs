// Builds the Windows desktop app:
//   1. builds the web vault and copies it into the app (it ships inside, never downloaded)
//   2. bundles the main and preload scripts
//   3. packages an NSIS installer into release/   (skip with --no-installer)
import { build as esbuild } from 'esbuild';
import { execSync } from 'node:child_process';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const repo = join(root, '..', '..');
const app = join(root, 'app');

rmSync(app, { recursive: true, force: true });
mkdirSync(app, { recursive: true });

console.log('• Building the web vault');
execSync('npm run build -w @enclavier/web', { cwd: repo, stdio: 'inherit' });
cpSync(join(repo, 'apps', 'web', 'dist'), join(app, 'web'), { recursive: true });

console.log('• Bundling the app');
const common = { bundle: true, platform: 'node', format: 'cjs', target: 'node22', external: ['electron'], minify: true, legalComments: 'none' };
await esbuild({ ...common, entryPoints: [join(root, 'src/main.ts')], outfile: join(app, 'main.cjs') });
await esbuild({ ...common, entryPoints: [join(root, 'src/preload.ts')], outfile: join(app, 'preload.cjs') });

mkdirSync(join(root, 'build'), { recursive: true });
const brand = join(repo, 'assets', 'brand');
cpSync(join(brand, 'icon-512.png'), join(root, 'build', 'icon.png'));
cpSync(join(brand, 'icon-256.png'), join(app, 'icon.png')); // window icon

if (!process.argv.includes('--no-installer')) {
  console.log('• Packaging the installer');
  const { build } = await import('electron-builder');
  // Electron is hoisted to the workspace root, so tell the packager exactly which version is installed.
  const electronVersion = JSON.parse(readFileSync(join(repo, 'node_modules', 'electron', 'package.json'), 'utf8')).version;
  const files = await build({ projectDir: root, win: ['nsis'], publish: 'never', config: { electronVersion } });
  console.log('Built:\n  ' + files.join('\n  '));
}
