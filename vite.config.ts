import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import seoFallback from './vite/seo-fallback.ts'
import blog from './vite/blog/plugin.ts'

export default defineConfig({
  plugins: [react(), tailwindcss(), seoFallback(), blog()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  build: {
    // The animation libraries are large and change rarely — give each its own
    // chunk so a content edit doesn't invalidate them in the browser cache.
    rollupOptions: {
      output: {
        codeSplitting: {
          groups: [
            { name: 'react', test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ },
            { name: 'gsap', test: /node_modules[\\/](gsap|@gsap)[\\/]/ },
            { name: 'motion', test: /node_modules[\\/]motion/ },
          ],
        },
      },
    },
  },
})
