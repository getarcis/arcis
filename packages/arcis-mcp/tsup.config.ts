import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/server.ts'],
  format: ['esm'],
  outExtension: () => ({ js: '.js' }),
  banner: {
    js: '#!/usr/bin/env node',
  },
  dts: false,
  clean: true,
  splitting: false,
  sourcemap: true,
  minify: false,
  shims: false,
  target: 'node18',
});
