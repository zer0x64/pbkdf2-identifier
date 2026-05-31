import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// https://vite.dev/config/
export default defineConfig({
  plugins: [svelte()],
  define: {
    __PBKDF2_DEBUG__: JSON.stringify(process.env.PBKDF2_DEBUG === 'true')
  }
})
