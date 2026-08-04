import {
  type DerivedVaultKey,
  decryptMnemonic,
  deriveVaultKey,
  encodeAddress,
  encryptMnemonic,
  exportVaultKey,
  generateMnemonic,
  importVaultKey,
  keyPairFromSeed,
  seedFromMnemonic,
} from '@warrenbrowse/sdk-core';

const VAULT_KEY = 'warren.vault';
const SESSION_KEY = 'warren.sessionKey';

/** An async key/value area (a `chrome.storage` area, or a fake in tests). */
export interface KeyringStorageArea {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

/** The two storage areas the keyring uses. */
export interface KeyringStorage {
  /** Persistent, on disk: holds the encrypted vault. */
  local: KeyringStorageArea;
  /** In-memory, cleared on browser close: holds the cached derived key. */
  session: KeyringStorageArea;
}

interface CachedKey {
  jwk: JsonWebKey;
}

/**
 * The wallet inside the extension: an encrypted mnemonic vault in
 * `storage.local`, unlocked by a password into memory. The derived key is
 * cached in `storage.session` (in-memory, never on disk) so the keyring can
 * rehydrate after the MV3 service worker is killed without re-prompting; the
 * cache dies with the browser session, forcing a password unlock next launch.
 *
 * The mnemonic never leaves the extension except, at connect time, to the
 * local native host over its IPC (a user-installed datapath, like a local
 * signer). It is never sent to a web page or over the network.
 */
export class WarrenKeyring {
  private readonly storage: KeyringStorage;
  private mnemonic: string | undefined;

  constructor(storage: KeyringStorage) {
    this.storage = storage;
  }

  /** Whether an encrypted vault exists (onboarding is needed if not). */
  async hasVault(): Promise<boolean> {
    return (await this.storage.local.get(VAULT_KEY)) !== undefined;
  }

  /** Whether the vault is currently unlocked in memory. */
  isUnlocked(): boolean {
    return this.mnemonic !== undefined;
  }

  /** Creates a fresh 12-word wallet, persists it encrypted, and unlocks it. */
  async create(password: string): Promise<string> {
    return this.store(generateMnemonic(), password);
  }

  /** Imports an existing mnemonic (validated), persists it encrypted, and unlocks it. */
  async import(mnemonic: string, password: string): Promise<void> {
    // Validate before writing anything: seedFromMnemonic throws on a bad phrase.
    seedFromMnemonic(mnemonic);
    await this.store(mnemonic, password);
  }

  private async store(mnemonic: string, password: string): Promise<string> {
    const blob = await encryptMnemonic(mnemonic, password);
    await this.storage.local.set(VAULT_KEY, blob);
    const parsed = JSON.parse(blob) as { kdf: { salt: string; iterations: number } };
    const derived = await deriveVaultKey(password, parsed.kdf.salt, parsed.kdf.iterations);
    await this.cacheKey(derived);
    this.mnemonic = mnemonic;
    return mnemonic;
  }

  /** Decrypts the vault with the password and caches the derived key. */
  async unlock(password: string): Promise<void> {
    const blob = await this.requireVault();
    const parsed = JSON.parse(blob) as { kdf: { salt: string; iterations: number } };
    const derived = await deriveVaultKey(password, parsed.kdf.salt, parsed.kdf.iterations);
    // decryptMnemonic with the derived key throws WarrenVaultError on a wrong password.
    this.mnemonic = await decryptMnemonic(blob, { key: derived.key });
    await this.cacheKey(derived);
  }

  /**
   * Re-decrypts the vault from the session-cached key after a service-worker
   * restart, with no password. Returns false when there is nothing to rehydrate
   * (browser was closed, cache cleared): the caller must show the unlock screen.
   */
  async rehydrate(): Promise<boolean> {
    const cachedJson = await this.storage.session.get(SESSION_KEY);
    const blob = await this.storage.local.get(VAULT_KEY);
    if (!cachedJson || !blob) return false;
    try {
      const cached = JSON.parse(cachedJson) as CachedKey;
      const key = await importVaultKey(cached.jwk);
      this.mnemonic = await decryptMnemonic(blob, { key });
      return true;
    } catch {
      // A stale or invalid cache is not fatal: fall back to the unlock screen.
      await this.storage.session.remove(SESSION_KEY);
      return false;
    }
  }

  /** Wipes the in-memory secret and the session-cached key (explicit or auto lock). */
  lock(): void {
    this.mnemonic = undefined;
    void this.storage.session.remove(SESSION_KEY);
  }

  /**
   * Irreversibly erases the wallet: the encrypted vault, the session-cached
   * key and the in-memory secret. Without the recovery phrase the account is
   * gone; callers must re-authenticate the user before invoking this.
   */
  async destroy(): Promise<void> {
    this.mnemonic = undefined;
    await this.storage.session.remove(SESSION_KEY);
    await this.storage.local.remove(VAULT_KEY);
  }

  /** The unlocked mnemonic. Handed only to the local native host at connect time. */
  async getMnemonic(): Promise<string> {
    if (this.mnemonic === undefined) throw new Error('keyring is locked');
    return this.mnemonic;
  }

  /** The account SS58 address (`wb...`). Available while unlocked. */
  async getAddress(): Promise<string> {
    if (this.mnemonic === undefined) throw new Error('keyring is locked');
    const seed = seedFromMnemonic(this.mnemonic);
    const address = encodeAddress(keyPairFromSeed(seed).publicKey);
    seed.fill(0);
    return address;
  }

  private async cacheKey(derived: DerivedVaultKey): Promise<void> {
    const jwk = await exportVaultKey(derived.key);
    await this.storage.session.set(SESSION_KEY, JSON.stringify({ jwk } satisfies CachedKey));
  }

  private async requireVault(): Promise<string> {
    const blob = await this.storage.local.get(VAULT_KEY);
    if (!blob) throw new Error('no vault to unlock');
    return blob;
  }
}

/** Adapts a `chrome.storage` area (callback or promise based) to {@link KeyringStorageArea}. */
export function chromeStorageArea(area: {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}): KeyringStorageArea {
  return {
    get: async (key) => {
      const got = await area.get(key);
      const value = got[key];
      return typeof value === 'string' ? value : undefined;
    },
    set: (key, value) => area.set({ [key]: value }),
    remove: (key) => area.remove(key),
  };
}
