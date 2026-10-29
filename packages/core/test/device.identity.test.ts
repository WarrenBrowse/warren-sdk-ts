import { describe, expect, it } from 'vitest';
import {
  DEVICE_NAME_ADJECTIVES,
  DEVICE_NAME_ANIMALS,
  type DeviceIdentity,
  InMemoryDeviceIdentityPersistence,
  WarrenDeviceError,
  deviceIdBytes,
  deviceNameFrom,
  deviceRegistration,
  encodeDeviceIdentity,
  forgetDeviceIdentity,
  generateDeviceIdentity,
  generateDeviceName,
  keepDeviceName,
  keptDeviceIdentity,
  parseDeviceId,
  parseDeviceIdentity,
} from '../src/index.js';

const ID = parseDeviceId('AAECAwQFBgcICQoLDA0ODw');

/** A deterministic u32 stream (xorshift32), standing in for the CSPRNG. */
function xorshift(seed: number): () => number {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x;
  };
}

describe('device names', () => {
  it('carries the same two word lists as the Rust SDK', () => {
    // warren-sdk-rs crates/warren-api/src/device.rs: every client names its
    // devices from these, whatever language it is written in.
    expect(DEVICE_NAME_ADJECTIVES).toEqual([
      'amber',
      'bold',
      'brave',
      'bright',
      'calm',
      'clever',
      'cosy',
      'crisp',
      'curious',
      'dapper',
      'eager',
      'fair',
      'gentle',
      'glad',
      'golden',
      'happy',
      'honest',
      'jolly',
      'keen',
      'kind',
      'lively',
      'lucky',
      'merry',
      'mighty',
      'nimble',
      'noble',
      'patient',
      'plucky',
      'proud',
      'quick',
      'quiet',
      'rapid',
      'shy',
      'silver',
      'sleek',
      'steady',
      'sunny',
      'swift',
      'tidy',
      'witty',
    ]);
    expect(DEVICE_NAME_ANIMALS).toEqual([
      'badger',
      'beaver',
      'bison',
      'crane',
      'deer',
      'dolphin',
      'eagle',
      'falcon',
      'ferret',
      'finch',
      'fox',
      'gecko',
      'hare',
      'hedgehog',
      'heron',
      'ibis',
      'jackal',
      'koala',
      'lemur',
      'lynx',
      'marten',
      'mole',
      'moose',
      'newt',
      'otter',
      'owl',
      'panda',
      'puffin',
      'rabbit',
      'raven',
      'robin',
      'seal',
      'sparrow',
      'squirrel',
      'stoat',
      'swan',
      'tapir',
      'toad',
      'walrus',
      'wolf',
    ]);
  });

  it('draws an adjective then an animal, each from its draw modulo the list length', () => {
    const draws = [4, 40 + 14];
    expect(deviceNameFrom(() => draws.shift() ?? 0)).toBe('calm heron');
  });

  it('reaches every word of both lists', () => {
    const next = xorshift(11);
    const adjectives = new Set<string>();
    const animals = new Set<string>();
    for (let i = 0; i < 4000; i++) {
      const [adjective, animal] = deviceNameFrom(next).split(' ');
      adjectives.add(adjective ?? '');
      animals.add(animal ?? '');
    }
    expect(adjectives.size).toBe(DEVICE_NAME_ADJECTIVES.length);
    expect(animals.size).toBe(DEVICE_NAME_ANIMALS.length);
  });

  it('generates a listed name from the CSPRNG', () => {
    const [adjective, animal] = generateDeviceName().split(' ');
    expect(DEVICE_NAME_ADJECTIVES).toContain(adjective);
    expect(DEVICE_NAME_ANIMALS).toContain(animal);
  });
});

describe('device identity', () => {
  it('draws sixteen random bytes, never twice the same', () => {
    const a = generateDeviceIdentity();
    const b = generateDeviceIdentity();
    expect(deviceIdBytes(a.deviceId)).toHaveLength(16);
    expect(a.deviceId).not.toBe(b.deviceId);
  });

  it('registers as the identity, on the platform, at the version', () => {
    const identity: DeviceIdentity = { deviceId: ID, name: 'calm heron' };

    expect(deviceRegistration(identity, 'browser', '0.1.8')).toEqual({
      device_id: 'AAECAwQFBgcICQoLDA0ODw',
      name: 'calm heron',
      platform: 'browser',
      app_version: '0.1.8',
    });
  });

  it('never registers as other: the registry refuses a platform outside its set', () => {
    const identity: DeviceIdentity = { deviceId: ID, name: 'calm heron' };

    expect(() => deviceRegistration(identity, 'other' as never, '0.1.8')).toThrow(
      WarrenDeviceError,
    );
  });

  it('is kept in the Rust SDK identity file format', () => {
    const identity: DeviceIdentity = { deviceId: ID, name: 'calm heron' };

    // warren-sdk serializes DeviceIdentity as {device_id, name}: the helper
    // and the Node engine read what this writes.
    const encoded = encodeDeviceIdentity(identity);

    expect(JSON.parse(encoded)).toEqual({
      device_id: 'AAECAwQFBgcICQoLDA0ODw',
      name: 'calm heron',
    });
    expect(parseDeviceIdentity(encoded)).toEqual(identity);
  });

  it('reads nothing from a file that is not an identity', () => {
    for (const text of [
      'not json',
      '{}',
      '{"device_id":"AAECAwQFBgcICQoLDA0O","name":"calm heron"}',
      '{"device_id":"AAECAwQFBgcICQoLDA0ODw","name":""}',
      '{"device_id":"AAECAwQFBgcICQoLDA0ODw","name":7}',
    ]) {
      expect(parseDeviceIdentity(text), text).toBeUndefined();
    }
  });
});

describe('kept device identity', () => {
  it('draws one on first use and reads the same one back', () => {
    const store = new InMemoryDeviceIdentityPersistence();

    const drawn = keptDeviceIdentity(store);

    expect(keptDeviceIdentity(store)).toEqual(drawn);
    expect(parseDeviceIdentity(store.load() ?? '')).toEqual(drawn);
  });

  it('replaces an unreadable one with a new draw, and keeps it', () => {
    const store = new InMemoryDeviceIdentityPersistence();
    store.save('garbage');

    const drawn = keptDeviceIdentity(store);

    expect(parseDeviceIdentity(store.load() ?? '')).toEqual(drawn);
  });

  it('keeps a rename for the next start', () => {
    const store = new InMemoryDeviceIdentityPersistence();
    const drawn = keptDeviceIdentity(store);

    expect(keepDeviceName(store, 'kitchen laptop')).toBe(true);

    expect(keptDeviceIdentity(store)).toEqual({ deviceId: drawn.deviceId, name: 'kitchen laptop' });
  });

  it('never keeps a name without the id it names', () => {
    const store = new InMemoryDeviceIdentityPersistence();

    expect(keepDeviceName(store, 'kitchen laptop')).toBe(false);
    expect(store.load()).toBeUndefined();
  });

  it('draws a new identity once the kept one is forgotten', () => {
    const store = new InMemoryDeviceIdentityPersistence();
    const before = keptDeviceIdentity(store);

    forgetDeviceIdentity(store);

    expect(store.load()).toBeUndefined();
    expect(keptDeviceIdentity(store).deviceId).not.toBe(before.deviceId);
  });
});
