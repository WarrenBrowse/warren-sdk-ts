import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  TokenManager,
  type TokenTransport,
  defaultTokenStorePath,
  fileTokenPersistence,
} from '../src/index.js';

const EPOCH_SECS = 86400;
const EPOCH = 42;
const NOW = EPOCH * EPOCH_SECS + 10;
const TOKEN_LEN = 354;

/** A store bundle carrying one pre-minted token for EPOCH. The token bytes are
 * opaque to the store (never verified), so a fixed pattern is enough to prove
 * the file seam feeds the manager. */
function bundleWithOneToken(fill: number): string {
  const token = Buffer.from(new Uint8Array(TOKEN_LEN).fill(fill)).toString('base64url');
  return JSON.stringify({ v: 1, epochSecs: EPOCH_SECS, epochs: { [EPOCH]: [token] } });
}

/** A transport that throws on any call: proves the file path needs no network. */
const offlineTransport: TokenTransport = {
  async getDirectory() {
    throw new Error('offline: getDirectory must not be called');
  },
  async issue() {
    throw new Error('offline: issue must not be called');
  },
};

describe('fileTokenPersistence', () => {
  it('round-trips a bundle, creating the dir 0700 and the file 0600', () => {
    const dir = mkdtempSync(join(tmpdir(), 'warren-tokstore-'));
    const path = join(dir, 'warren', 'tokens.json');
    const persistence = fileTokenPersistence(path);

    // Missing file reads as "nothing persisted" (fail closed to empty).
    expect(persistence.load()).toBeUndefined();

    const body = bundleWithOneToken(0x11);
    persistence.save(body);
    expect(persistence.load()).toBe(body);

    // Restrictive modes are a POSIX concept; Windows has no 0600 bits.
    if (process.platform !== 'win32') {
      expect(statSync(path).mode & 0o777).toBe(0o600);
      expect(statSync(join(dir, 'warren')).mode & 0o777).toBe(0o700);
    }
  });

  it('feeds a TokenManager across a restart with no network and holds no seed', () => {
    const dir = mkdtempSync(join(tmpdir(), 'warren-tokstore-'));
    const path = join(dir, 'tokens.json');
    fileTokenPersistence(path).save(bundleWithOneToken(0x22));

    // "Restart": a fresh manager over the persisted file, offline transport.
    const mgr = new TokenManager(offlineTransport, fileTokenPersistence(path));
    expect(mgr.available(EPOCH)).toBe(1);
    const stack = mgr.takeCurrentStack(NOW);
    expect(stack).toHaveLength(1);
    expect(stack[0]!.length).toBe(TOKEN_LEN);
    expect(mgr.available(EPOCH)).toBe(0);

    // The consuming pop was written back through the file seam.
    const restarted = new TokenManager(offlineTransport, fileTokenPersistence(path));
    expect(restarted.available(EPOCH)).toBe(0);

    // The store is tokens only: never the wallet mnemonic or the word "mnemonic".
    const onDisk = readFileSync(path, 'utf8').toLowerCase();
    expect(onDisk).not.toContain('mnemonic');
    expect(onDisk).not.toContain('embrace'); // a word from the baked team seed
  });
});

describe('defaultTokenStorePath', () => {
  it('defaults under ~/.config/warren and honors WARREN_TOKEN_STORE', () => {
    const home = join('home', 'user');
    expect(defaultTokenStorePath({}, home)).toBe(join(home, '.config', 'warren', 'tokens.json'));
    expect(defaultTokenStorePath({ WARREN_TOKEN_STORE: '/custom/t.json' }, home)).toBe(
      '/custom/t.json',
    );
  });
});
