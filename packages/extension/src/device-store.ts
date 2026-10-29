/**
 * `chrome.storage`-backed {@link DeviceIdentityPersistence} for a Manifest V3
 * background: the browser install's identity in the account's device registry
 * (warren-core doc 115).
 *
 * The extension owns this identity, not the helper: the browser-proxy tier
 * mints and spends credentials with no helper installed, so the extension is
 * the one part present on every path. It registers it from its own token
 * refresh and hands it to the host on connect (`device` in the connect
 * request), so the install is one line in the account's list whichever tier
 * carries the browser. It lives in `chrome.storage.local` beside the token
 * bundles, so it outlives the service worker, an update and a restart, and
 * goes with the extension when it is removed.
 *
 * {@link DeviceIdentityPersistence} is synchronous and `chrome.storage` is not,
 * so the identity is read ONCE at {@link openDeviceIdentityStore} and served
 * from memory afterwards; writes go through in the background, in order, and
 * {@link DeviceIdentityStore.flush} waits for them.
 */

import type { DeviceIdentityPersistence } from '@warrenbrowse/sdk-core';
import type { TokenStorageArea } from './token-store.js';

/** Storage key holding the kept device identity. */
export const DEVICE_IDENTITY_KEY = 'warren.deviceIdentity';

/** The `chrome.storage` surface this module needs (promise flavour). */
export interface DeviceIdentityStorageArea extends TokenStorageArea {
  remove(key: string): Promise<void>;
}

export interface DeviceIdentityStore {
  /** Hand this to `keptDeviceIdentity`, `keepDeviceName` and `forgetDeviceIdentity`. */
  readonly persistence: DeviceIdentityPersistence;
  /** Resolves once every queued write has settled. Never rejects. */
  flush(): Promise<void>;
}

/**
 * Reads the identity at `key` and returns a persistence over it. Never throws:
 * unreadable storage reads as no identity kept.
 */
export async function openDeviceIdentityStore(
  area: DeviceIdentityStorageArea,
  key: string = DEVICE_IDENTITY_KEY,
): Promise<DeviceIdentityStore> {
  let text: string | undefined;
  try {
    const value = (await area.get(key))[key];
    if (typeof value === 'string') text = value;
  } catch {
    // Read as none kept: the caller draws one and the next save rewrites it.
  }

  // Chained so a save and a removal in one tick land in the order they were made.
  let queue: Promise<void> = Promise.resolve();
  const enqueue = (write: () => Promise<void>) => {
    queue = queue.then(() => write().catch(() => undefined));
  };

  const persistence: DeviceIdentityPersistence = {
    load: () => text,
    save: (serialized: string) => {
      text = serialized;
      enqueue(() => area.set({ [key]: serialized }));
    },
    remove: () => {
      text = undefined;
      enqueue(() => area.remove(key));
    },
  };

  return { persistence, flush: () => queue };
}
