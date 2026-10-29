import { keptDeviceIdentity, parseDeviceIdentity } from '@warrenbrowse/sdk-core';
import { describe, expect, it, vi } from 'vitest';
import { DEVICE_IDENTITY_KEY, openDeviceIdentityStore } from '../src/device-store.js';

/** A `chrome.storage` area stand-in: the boundary this module exists to cross. */
function fakeArea(initial: Record<string, unknown> = {}) {
  const items = { ...initial };
  return {
    items,
    get: vi.fn(async (key: string) => (key in items ? { [key]: items[key] } : {})),
    set: vi.fn(async (next: Record<string, unknown>) => {
      Object.assign(items, next);
    }),
    remove: vi.fn(async (key: string) => {
      delete items[key];
    }),
  };
}

const KEPT = '{"device_id":"AAECAwQFBgcICQoLDA0ODw","name":"calm heron"}';

describe('openDeviceIdentityStore', () => {
  it('reads back the identity a previous worker kept', async () => {
    const store = await openDeviceIdentityStore(fakeArea({ [DEVICE_IDENTITY_KEY]: KEPT }));

    expect(keptDeviceIdentity(store.persistence)).toEqual(parseDeviceIdentity(KEPT));
  });

  it('keeps a first draw in storage, so the next worker registers the same device', async () => {
    const area = fakeArea();
    const store = await openDeviceIdentityStore(area);
    const first = keptDeviceIdentity(store.persistence);
    await store.flush();

    const next = await openDeviceIdentityStore(area);

    expect(keptDeviceIdentity(next.persistence)).toEqual(first);
  });

  it('removes the identity from storage once forgotten', async () => {
    const area = fakeArea({ [DEVICE_IDENTITY_KEY]: KEPT });
    const store = await openDeviceIdentityStore(area);

    store.persistence.remove();
    await store.flush();

    expect(store.persistence.load()).toBeUndefined();
    expect(DEVICE_IDENTITY_KEY in area.items).toBe(false);
  });

  it('starts empty over storage it cannot read', async () => {
    const area = fakeArea();
    area.get.mockRejectedValueOnce(new Error('storage unavailable'));

    const store = await openDeviceIdentityStore(area);

    expect(store.persistence.load()).toBeUndefined();
  });
});
