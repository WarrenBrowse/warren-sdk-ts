import { defineConfig } from 'tsup';

// Bakes the release channel into the bundle so a published artifact cannot be
// repointed at the other channel by a stray runtime env var. Validated here so
// a typo fails the build instead of silently shipping prod.
function resolveProductEnv(): string {
  const value = process.env.WARREN_PRODUCT_ENV?.trim() || 'prod';
  if (value !== 'prod' && value !== 'beta') {
    throw new Error(`WARREN_PRODUCT_ENV must be prod or beta (or unset for prod), got: ${value}`);
  }
  return value;
}

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  define: {
    WARREN_PRODUCT_ENV: JSON.stringify(resolveProductEnv()),
  },
});
