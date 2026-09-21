import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/test/**/*.test.ts'],
    // The Windows CI leg is an emulated ARM64 QEMU VM on the shared Mac Studio;
    // the Argon2 KDF crypto suites (WarrenVault, WarrenKeyring) run 5-7x slower
    // there and intermittently blow vitest's 5s default under host load, redding
    // the whole js (windows) matrix leg. A generous timeout on that leg removes
    // the flake without weakening any assertion (a genuine hang still fails).
    // The vault's export/import test derives twice and took 35 s there on
    // 2026-09-21, past the previous 30 s. The coverage leg shares that host and
    // its instrumented KDF tests crossed 10 s the same day, so every leg gets
    // a bound that only a hang can reach.
    testTimeout: process.platform === 'win32' ? 120000 : 60000,
    hookTimeout: process.platform === 'win32' ? 120000 : 60000,
    coverage: {
      provider: 'v8',
      include: ['packages/*/src/**/*.ts'],
      // The proxy facade and the native-host runtime only run with the native
      // addon / real stdio, absent in CI; exclude them so coverage reflects
      // the testable pure-TS surface.
      exclude: ['packages/node/src/proxy/**', 'packages/extension/src/host/run.ts'],
      reporter: ['text-summary', 'json-summary'],
      thresholds: { lines: 85, functions: 85, statements: 85, branches: 75 },
    },
  },
});
