import { defineConfig } from 'vite';

export default defineConfig({
  base: '/phantom-vault/',
  build: {
    outDir: 'out',
    emptyOutDir: true,
  },
});
