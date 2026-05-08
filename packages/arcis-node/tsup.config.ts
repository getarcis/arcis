import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'index': 'src/index.ts',
    'core/index': 'src/core/index.ts',
    'sanitizers/index': 'src/sanitizers/index.ts',
    'middleware/index': 'src/middleware/index.ts',
    'fastify/index': 'src/middleware/fastify.ts',
    'nestjs/index': 'src/middleware/nestjs.ts',
    'nextjs/index': 'src/middleware/nextjs.ts',
    'sveltekit/index': 'src/middleware/sveltekit.ts',
    'astro/index': 'src/middleware/astro.ts',
    'nuxt/index': 'src/middleware/nuxt.ts',
    'bun/index': 'src/middleware/bun.ts',
    'validation/index': 'src/validation/index.ts',
    'logging/index': 'src/logging/index.ts',
    'stores/index': 'src/stores/index.ts',
    'utils/index': 'src/utils/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: false,
  clean: true,
  splitting: false,
  sourcemap: true,
  minify: false,
  treeshake: true,
  outExtension({ format }) {
    return {
      js: format === 'cjs' ? '.js' : '.mjs',
    };
  },
});
