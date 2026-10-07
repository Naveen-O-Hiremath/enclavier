import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Extension pages (popup, in-page login picker, offscreen clipboard helper).
// The background worker and content script are bundled by build.mjs.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: './',
  build: {
    outDir: 'dist/.pages',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
    modulePreload: false,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        inline: resolve(__dirname, 'inline.html'),
        offscreen: resolve(__dirname, 'offscreen.html'),
      },
    },
  },
});
