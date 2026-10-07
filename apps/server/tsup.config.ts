import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts', migrate: 'src/cli/migrate.ts', 'verify-audit': 'src/cli/verify-audit.ts', 'test-mail': 'src/cli/test-mail.ts' },
  format: ['esm'],
  target: 'node20',
  platform: 'node',
  clean: true,
  sourcemap: true,
  // Workspace packages ship TypeScript source, so bundle them in.
  noExternal: [/^@enclavier\//],
});
