import { fileURLToPath, URL } from 'node:url'
import process from 'node:process'
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

const backendTarget = process.env.WEB_STARTER_API_TARGET ?? 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target: backendTarget,
        changeOrigin: true,
      },
      '/oauth2': {
        target: backendTarget,
        changeOrigin: true,
      },
      '/connect': {
        target: backendTarget,
        changeOrigin: true,
      },
      '/.well-known': {
        target: backendTarget,
        changeOrigin: true,
      },
      '/mcp': {
        target: backendTarget,
        changeOrigin: true,
      },
    },
  },
  preview: {
    host: '0.0.0.0',
    port: 4173,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    css: true,
  },
})
