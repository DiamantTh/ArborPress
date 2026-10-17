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
        webauthn: resolve(frontendRoot, 'src/entries/webauthn.ts'),
      },
    },
  },
})
