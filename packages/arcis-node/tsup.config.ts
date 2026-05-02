import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'index': 'src/index.ts',
    'core/index': 'src/core/index.ts',
    'sanitizers/index': 'src/sanitizers/index.ts',
    'middleware/index': 'src/middleware/index.ts',
    'validation/index': 'src/validation/index.ts',
    'logging/index': 'src/logging/index.ts',
    'stores/index': 'src/stores/index.ts',
    'utils/index': 'src/utils/index.ts',
    // Node CLI binary. package.json's "bin" points at ./dist/cli/arcis.mjs
    // so the ESM build is the canonical entry. Shebang prepended via
    // banner below so the file is executable when npm symlinks it.
    'cli/arcis': 'src/cli/arcis.ts',
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
