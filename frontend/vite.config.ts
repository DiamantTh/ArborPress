import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { svelte, vitePreprocess } from '@sveltejs/vite-plugin-svelte'
import { defineConfig } from 'vite'

const frontendRoot = fileURLToPath(new URL('.', import.meta.url))

export default defineConfig({
  plugins: [svelte({ preprocess: vitePreprocess() })],
  build: {
    outDir: resolve(frontendRoot, '../arborpress/static/dist'),
    emptyOutDir: true,
    manifest: '.vite/manifest.json',
    rollupOptions: {
      input: {
        site: resolve(frontendRoot, 'src/entries/site.ts'),
        public: resolve(frontendRoot, 'src/entries/public.ts'),
        webauthn: resolve(frontendRoot, 'src/entries/webauthn.ts'),
        'auth-security': resolve(frontendRoot, 'src/entries/auth-security.ts'),
        'auth-mfa': resolve(frontendRoot, 'src/entries/auth-mfa.ts'),
        'notifications-live': resolve(frontendRoot, 'src/entries/notifications-live.ts'),
        'notifications-webpush': resolve(frontendRoot, 'src/entries/notifications-webpush.ts'),
        'webauthn-register': resolve(frontendRoot, 'src/entries/webauthn-register.ts'),
        admin: resolve(frontendRoot, 'src/entries/admin.ts'),
        editor: resolve(frontendRoot, 'src/entries/editor.ts'),
        'editor-tiptap': resolve(frontendRoot, 'src/ap-editor/tiptap/index.ts'),
      },
    },
  },
})
