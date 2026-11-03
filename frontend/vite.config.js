import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // the dashboard calls /api/... and vite passes it on to the backend, so only
    // this one port has to be reachable (works through a forwarded/shared link)
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        ws: true,   // live alerts websocket
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
