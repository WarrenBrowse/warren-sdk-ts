/**
 * `chrome.storage`-backed {@link TokenPersistence} for a Manifest V3 background.
 *
 * Why this exists: a v3 service worker is torn down after a few seconds of
 * inactivity, so an in-memory token store is empty again on the next wake, and
 * the issuer refuses to re-sign an epoch it has already issued to the account
 * (once-per-account-epoch). An extension that keeps its pre-minted tokens in RAM
 * therefore loses them for good and reports "no pre-minted session tokens for
 * this epoch" on every connect that follows a teardown. The bundle has to
 * outlive the worker.
 *
 * What lands in storage is the same bundle the Node SDK writes to disk: only
 * redeemable anonymous bearer tokens plus the published epoch length, never the
 * mnemonic or the pubkey. The blind-RSA construction already unlinks the tokens
 * from the account, so a read of this area yields bounded, unlinkable
 * credentials and no identity.
 *
 * {@link TokenPersistence} is synchronous and `chrome.storage` is not, so the
 * bundle is read ONCE at {@link openTokenStore} and served from memory
 * afterwards; saves write through in the background, serialized, and
 * {@link TokenStore.flush} waits for them.
 */

import type { TokenPersistence } from '@warrenbrowse/sdk-core';

/** Storage key holding the serialized session-token bundle. */
export const TOKEN_BUNDLE_KEY = 'warren.tokenBundle';

/** Storage key for the browser-proxy credential bundle. A key of its own
 * because the two credential classes are minted from different issuer keys and
 * spent at different places: one store holding both would vend a session token
 * to the proxy, which every ingress refuses. */
export const BROWSER_PROXY_BUNDLE_KEY = 'warren.browserProxyBundle';

/** The `chrome.storage` surface this module needs (promise flavour). */
export interface TokenStorageArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

export interface TokenStore {
  /** Hand this to a `TokenManager`. */
  readonly persistence: TokenPersistence;
  /** Resolves once every queued write has settled. Never rejects: a failed
   * write leaves the value in memory, and since the bundle is always the full
   * state, the next save overwrites whatever did or did not land. */
  flush(): Promise<void>;
}

/**
 * Reads the bundle at `key` and returns a {@link TokenPersistence} over it.
 *
 * Never throws: an unreadable area yields an empty store, which the manager
 * treats as "nothing pre-minted" and heals on its next refresh.
 */
export async function openTokenStore(
  area: TokenStorageArea,
  key: string = TOKEN_BUNDLE_KEY,
): Promise<TokenStore> {
  let bundle: string | undefined;
  try {
    const got = await area.get(key);
    const value = got[key];
    if (typeof value === 'string') bundle = value;
  } catch {
    // Unreadable storage is indistinguishable from an empty one for our
    // purposes: start empty rather than fail the whole background.
  }

  // Writes are chained rather than fired in parallel so two saves in the same
  // tick cannot land out of order and leave an older bundle on disk.
  let queue: Promise<void> = Promise.resolve();

  const persistence: TokenPersistence = {
    load: () => bundle,
    save: (serialized: string) => {
      bundle = serialized;
      queue = queue.then(() =>
        area.set({ [key]: serialized }).catch(() => {
          // Kept in memory above; the next save rewrites the whole bundle.
        }),
      );
    },
  };

  return { persistence, flush: () => queue };
}
