import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
    },
  },
  resolve: {
    alias: {
      '@core': path.resolve(__dirname, 'src/core'),
      '@scanners': path.resolve(__dirname, 'src/scanners'),
      '@integrations': path.resolve(__dirname, 'src/integrations'),
      '@analysis': path.resolve(__dirname, 'src/analysis'),
      '@reports': path.resolve(__dirname, 'src/reports'),
      '@storage': path.resolve(__dirname, 'src/storage'),
      '@config': path.resolve(__dirname, 'src/config'),
      '@i18n': path.resolve(__dirname, 'src/i18n'),
      '@utils': path.resolve(__dirname, 'src/utils'),
      '@': path.resolve(__dirname, 'src'),
    },
  },
});
