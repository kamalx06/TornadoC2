import { defineConfig, externalizeDepsPlugin } from 'electron-vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()],
    build: { lib: { entry: resolve('src/main/index.ts') } }
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
    build: { lib: { entry: resolve('src/preload/index.ts') } }
  },
  renderer: {
    root: resolve('src/renderer'),
    plugins: [react()],
    build: {
      chunkSizeWarningLimit: 700,
      rollupOptions: {
        input: resolve('src/renderer/index.html'),
        output: {
          manualChunks(id) {
            if (!id.includes('node_modules')) return
            if (id.includes('react-resizable-panels')) return 'dock'
            if (/node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return 'react'
            if (id.includes('@tanstack')) return 'virtual'
            if (/node_modules[\\/]d3-/.test(id)) return 'd3'
          }
        }
      }
    }
  }
})
