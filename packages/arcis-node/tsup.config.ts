import { join } from 'node:path';
import { type Options, defineConfig } from 'tsup';

type EsbuildPlugin = NonNullable<Options['esbuildPlugins']>[number];

/**
 * parse5 is ES-module only. The ESM build imports it statically; the CJS
 * build swaps in a loader that require()s it and reports a missing install
 * (see src/html/load-parse5.cjs.ts).
 */
const parse5LoaderForCjs: EsbuildPlugin = {
  name: 'html-parse5-loader-cjs',
  setup(build) {
    // tsup runs esbuild in ESM format when treeshaking and records the
    // target format in this define.
    if (build.initialOptions.define?.TSUP_FORMAT !== '"cjs"') {
      return;
    }
    build.onResolve({ filter: /^\.\/load-parse5$/ }, (args) => ({
      path: join(args.resolveDir, 'load-parse5.cjs.ts'),
    }));
  },
};

export default defineConfig({
  entry: {
    'index': 'src/index.ts',
    'core/index': 'src/core/index.ts',
    'sanitizers/index': 'src/sanitizers/index.ts',
    'html/index': 'src/html/index.ts',
    'middleware/index': 'src/middleware/index.ts',
    'fastify/index': 'src/middleware/fastify.ts',
    'koa/index': 'src/middleware/koa.ts',
    'nestjs/index': 'src/middleware/nestjs.ts',
    'nextjs/index': 'src/middleware/nextjs.ts',
    'sveltekit/index': 'src/middleware/sveltekit.ts',
    'astro/index': 'src/middleware/astro.ts',
    'nuxt/index': 'src/middleware/nuxt.ts',
    'bun/index': 'src/middleware/bun.ts',
    'hono/index': 'src/middleware/hono.ts',
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
  esbuildPlugins: [parse5LoaderForCjs],
  outExtension({ format }) {
    return {
      js: format === 'cjs' ? '.js' : '.mjs',
    };
  },
});
