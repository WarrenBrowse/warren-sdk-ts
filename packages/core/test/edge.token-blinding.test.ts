import { bytesToHex } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import { blindingKeyFromSeed, deterministicTokenRandom } from '../src/index.js';

const SEED = new Uint8Array(32).fill(7);
const OTHER_SEED = new Uint8Array(32).fill(8);

function stream(key: Uint8Array, epoch: number, index: number, len = 64): string {
  return bytesToHex(deterministicTokenRandom(key, epoch, index)(len));
}

describe('wallet-derived blinding material', () => {
  it('rebuilds the same stream from the same wallet, which is what lets a lost batch be re-asked', () => {
    const a = blindingKeyFromSeed(SEED, 'browser-proxy');
    const b = blindingKeyFromSeed(new Uint8Array(SEED), 'browser-proxy');
    expect(bytesToHex(a)).toBe(bytesToHex(b));
    expect(stream(a, 497_194, 0)).toBe(stream(b, 497_194, 0));
  });

  it('gives every epoch and every slot its own material, or a batch would repeat a credential', () => {
    const key = blindingKeyFromSeed(SEED, 'browser-proxy');
    const base = stream(key, 497_194, 0);
    expect(stream(key, 497_195, 0)).not.toBe(base);
    expect(stream(key, 497_194, 1)).not.toBe(base);
  });

  it('separates purposes, so a browser credential never derives from the tunnel stream', () => {
    const browser = blindingKeyFromSeed(SEED, 'browser-proxy');
    const session = blindingKeyFromSeed(SEED, 'session');
    expect(bytesToHex(browser)).not.toBe(bytesToHex(session));
    expect(stream(browser, 497_194, 0)).not.toBe(stream(session, 497_194, 0));
  });

  it('separates wallets, so two accounts never derive the same credentials', () => {
    expect(stream(blindingKeyFromSeed(SEED, 'browser-proxy'), 1, 0)).not.toBe(
      stream(blindingKeyFromSeed(OTHER_SEED, 'browser-proxy'), 1, 0),
    );
  });

  it('keeps the wallet seed out of the key it hands on', () => {
    const key = blindingKeyFromSeed(SEED, 'browser-proxy');
    expect(key).toHaveLength(32);
    expect(bytesToHex(key)).not.toBe(bytesToHex(SEED));
  });

  it('runs on past the first block, so a 256-byte draw is not a repeated 32-byte one', () => {
    const key = blindingKeyFromSeed(SEED, 'browser-proxy');
    const long = deterministicTokenRandom(key, 1, 0)(256);
    expect(bytesToHex(long.subarray(0, 32))).not.toBe(bytesToHex(long.subarray(32, 64)));
    // And a short draw is the prefix of the same stream, not a fresh one.
    expect(bytesToHex(deterministicTokenRandom(key, 1, 0)(32))).toBe(
      bytesToHex(long.subarray(0, 32)),
    );
  });

  it('advances with each draw, so the nonce, the salt and the blind differ', () => {
    const key = blindingKeyFromSeed(SEED, 'browser-proxy');
    const draw = deterministicTokenRandom(key, 1, 0);
    const first = bytesToHex(draw(32));
    const second = bytesToHex(draw(32));
    expect(second).not.toBe(first);
  });
});
