import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// In development the Rust demo server (`cargo run -p pramana-demo`) serves the API
// on :8080; Vite proxies /api to it so the app is same-origin, exactly as in production.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: { '/api': 'http://127.0.0.1:8080' },
  },
  build: { target: 'es2022', chunkSizeWarningLimit: 900 },
})
