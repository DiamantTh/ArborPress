/**
 * Standalone Vite-Build-Konfiguration für Editor-Adapter-Bundles.
 * Baut IIFE-Bundles ohne CDN-Abhängigkeiten in den statischen Ordner.
 *
 * Verwendung:
 *   npm run build:editor
 */
import { resolve } from 'path'
import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    lib: {
      // Mehrere Editor-Adapter-Bundles über rollupOptions.input
      entry: resolve(__dirname, 'src/ap-editor/tiptap/index.ts'),
      name: 'ArborPressTiptap',
      formats: ['iife'],
      fileName: () => 'tiptap.js',
    },
    outDir: resolve(__dirname, '../arborpress/static/js/editor-adapters'),
    emptyOutDir: false,
    rollupOptions: {
      // Kein window.ArborPressEditor als Extern – wir rufen es zur Laufzeit auf
      output: {
        // IIFE hat keinen Default-Export, alles inline
        inlineDynamicImports: true,
      },
    },
    // Source-Maps für Debugging in Dev-Umgebungen
    sourcemap: true,
    minify: 'esbuild',
    target: 'es2020',
  },
  resolve: {
    alias: {
      '$lib': resolve(__dirname, 'src/lib'),
    },
  },
})
