import { defineConfig } from 'tsup';

// The example extension bundle: a single self-contained ESM file for the MV3
// service worker. Unlike the library build, this inlines the workspace and
// crypto deps (noble/scure) so the browser has no bare imports to resolve.
export default defineConfig({
  entry: { 'sdk-extension': 'src/index.ts' },
  outDir: 'example',
  format: ['esm'],
  platform: 'browser',
  dts: false,
  sourcemap: false,
  clean: false,
  treeshake: true,
  noExternal: [/@warrenbrowse\//, /@noble\//, /@scure\//],
});
