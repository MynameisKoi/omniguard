import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // allow the dashboard to be opened through a tunnel (e.g. a trycloudflare
    // link) so a phone can reach it over HTTPS for web-push testing/demo
    allowedHosts: ['.trycloudflare.com', '.ngrok-free.app', '.ngrok.io'],
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
