import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: 'localhost',
    proxy: {
      '/auth': 'http://localhost:8000',
      '/cases': 'http://localhost:8000',
      '/alerts': 'http://localhost:8000',
      '/stats': 'http://localhost:8000',
      '/upload': 'http://localhost:8000',
      '/search': 'http://localhost:8000',
      '/graph': 'http://localhost:8000',
      '/timeline': 'http://localhost:8000',
      '/reports': 'http://localhost:8000',
    }
  }
})
