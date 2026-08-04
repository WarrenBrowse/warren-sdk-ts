import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  InMemoryGenerationStore,
  InMemoryServerKeyStore,
  type WarrenDirectoryError,
  type WarrenDiscoveryError,
  acceptMultihopDirectory,
  acceptSignedRelayList,
} from '../src/index.js';

function loadVector(name: string): { signed_json: string } & Record<string, unknown> {
  return JSON.parse(
    readFileSync(fileURLToPath(new URL(`../../../vectors/${name}`, import.meta.url)), 'utf8'),
  );
}

const relaysVector = loadVector('relays.json');
const listJson =
  typeof relaysVector.signed_json === 'string'
    ? relaysVector.signed_json
    : JSON.stringify(relaysVector.signed_json);
const directoryVector = loadVector('multihop_directory.json');
const directoryJson =
  typeof directoryVector.signed_json === 'string'
    ? directoryVector.signed_json
    : JSON.stringify(directoryVector.signed_json);

function expectError(fn: () => unknown): WarrenDiscoveryError | WarrenDirectoryError {
  try {
    fn();
  } catch (e) {
    return e as WarrenDiscoveryError;
  }
  throw new Error('expected a throw');
}

describe('acceptSignedRelayList (anti-rollback + TOFU)', () => {
  const parsed = JSON.parse(listJson);
  const freshNow = parsed.signed_at + 1;

  it('verifies, enforces expiry from the injected clock, and records the floor', () => {
    const generationStore = new InMemoryGenerationStore();
    const verified = acceptSignedRelayList(listJson, { generationStore, now: freshNow });
    expect(verified.relays.length).toBeGreaterThan(0);
    expect(generationStore.loadFloor()).toBe(verified.generation);
  });

  it('rejects an expired list with code expired', () => {
    const err = expectError(() => acceptSignedRelayList(listJson, { now: parsed.expires_at }));
    expect(err.code).toBe('expired');
  });

  it('rejects a generation below the stored floor with code rolled_back', () => {
    const generationStore = new InMemoryGenerationStore();
    generationStore.storeFloor(parsed.generation + 1);
    const err = expectError(() =>
      acceptSignedRelayList(listJson, { generationStore, now: freshNow }),
    );
    expect(err.code).toBe('rolled_back');
    // A rejected list must not raise the floor.
    expect(generationStore.loadFloor()).toBe(parsed.generation + 1);
  });

  it('pins the server key on first use and enforces it afterwards', () => {
    const serverKeyStore = new InMemoryServerKeyStore();
    const verified = acceptSignedRelayList(listJson, { serverKeyStore, now: freshNow });
    expect(serverKeyStore.loadPin()).toBe(verified.serverPubkeyHex);

    // Same list again: the remembered pin matches, accepted.
    acceptSignedRelayList(listJson, { serverKeyStore, now: freshNow });

    // A pre-poisoned store pins a different key: the fetch must fail.
    const poisoned = new InMemoryServerKeyStore();
    poisoned.storePin('00'.repeat(32));
    const err = expectError(() =>
      acceptSignedRelayList(listJson, { serverKeyStore: poisoned, now: freshNow }),
    );
    expect(err.code).toBe('server_pubkey_mismatch');
  });

  it('an explicit pin set takes precedence over the TOFU store', () => {
    const serverKeyStore = new InMemoryServerKeyStore();
    serverKeyStore.storePin('00'.repeat(32)); // would reject if consulted
    const verified = acceptSignedRelayList(listJson, {
      pins: [parsed.server_pubkey_hex],
      serverKeyStore,
      now: freshNow,
    });
    // Explicit pins also mean TOFU must not overwrite the store.
    expect(verified.relays.length).toBeGreaterThan(0);
    expect(serverKeyStore.loadPin()).toBe('00'.repeat(32));
  });
});

describe('acceptMultihopDirectory (anti-rollback + TOFU)', () => {
  const dirParsed = JSON.parse(directoryJson);
  const freshNow = dirParsed.signed_at + 1;

  it('verifies, records the floor, and pins TOFU', () => {
    const generationStore = new InMemoryGenerationStore();
    const serverKeyStore = new InMemoryServerKeyStore();
    const dir = acceptMultihopDirectory(directoryJson, {
      generationStore,
      serverKeyStore,
      now: freshNow,
    });
    expect(dir.exits.length).toBeGreaterThan(0);
    expect(generationStore.loadFloor()).toBe(dir.generation);
    expect(serverKeyStore.loadPin()).toBe(dir.serverPubkeyHex);
  });

  it('rejects expiry and rollback with typed codes', () => {
    expect(
      expectError(() => acceptMultihopDirectory(directoryJson, { now: dirParsed.expires_at })).code,
    ).toBe('expired');
    const generationStore = new InMemoryGenerationStore();
    generationStore.storeFloor(dirParsed.generation + 1);
    expect(
      expectError(() => acceptMultihopDirectory(directoryJson, { generationStore, now: freshNow }))
        .code,
    ).toBe('rolled_back');
  });
});

describe('in-memory stores', () => {
  it('the generation store keeps the maximum seen', () => {
    const store = new InMemoryGenerationStore();
    expect(store.loadFloor()).toBe(0);
    store.storeFloor(5);
    store.storeFloor(3);
    expect(store.loadFloor()).toBe(5);
  });

  it('the key store returns undefined until a pin is stored', () => {
    const store = new InMemoryServerKeyStore();
    expect(store.loadPin()).toBeUndefined();
    store.storePin('ab');
    expect(store.loadPin()).toBe('ab');
  });
});
