import { WarrenVaultError } from '@warrenbrowse/sdk-core';
import { describe, expect, it } from 'vitest';
import { type KeyringStorage, WarrenKeyring } from '../src/keyring.js';

/** In-memory fakes for chrome.storage.local (persistent) and .session (volatile). */
function fakeStorage(): {
  storage: KeyringStorage;
  local: Map<string, string>;
  session: Map<string, string>;
} {
  const local = new Map<string, string>();
  const session = new Map<string, string>();
  const area = (m: Map<string, string>) => ({
    get: async (k: string) => m.get(k),
    set: async (k: string, v: string) => void m.set(k, v),
    remove: async (k: string) => void m.delete(k),
  });
  return { storage: { local: area(local), session: area(session) }, local, session };
}

const PASSWORD = 'correct horse battery staple';

describe('WarrenKeyring', () => {
  it('reports no vault before one is created', async () => {
    const { storage } = fakeStorage();
    expect(await new WarrenKeyring(storage).hasVault()).toBe(false);
  });

  it('creates a vault, returns a backupable mnemonic, and unlocks to a wb address', async () => {
    const { storage, local } = fakeStorage();
    const kr = new WarrenKeyring(storage);

    const mnemonic = await kr.create(PASSWORD);

    expect(mnemonic.split(' ')).toHaveLength(12);
    expect(kr.isUnlocked()).toBe(true);
    expect((await kr.getAddress()).startsWith('wb')).toBe(true);
    // The vault is persisted encrypted: the phrase must not appear in cleartext.
    // A single word proves nothing, since one can be a key of the vault JSON.
    expect(local.get('warren.vault')).toBeDefined();
    expect(local.get('warren.vault')).not.toContain(mnemonic.split(' ').slice(0, 3).join(' '));
  });

  it('imports an existing mnemonic', async () => {
    const { storage } = fakeStorage();
    const kr = new WarrenKeyring(storage);
    const mnemonic = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

    await kr.import(mnemonic, PASSWORD);

    expect(kr.isUnlocked()).toBe(true);
    expect(await kr.getMnemonic()).toBe(mnemonic);
  });

  it('rejects importing an invalid mnemonic before writing any vault', async () => {
    const { storage, local } = fakeStorage();
    const kr = new WarrenKeyring(storage);
    await expect(kr.import('not a valid mnemonic phrase at all nope', PASSWORD)).rejects.toThrow();
    expect(local.size).toBe(0);
  });

  it('locks: clears the in-memory secret and the session-cached key', async () => {
    const { storage, session } = fakeStorage();
    const kr = new WarrenKeyring(storage);
    await kr.create(PASSWORD);
    expect(session.size).toBeGreaterThan(0);

    kr.lock();

    expect(kr.isUnlocked()).toBe(false);
    expect(session.size).toBe(0);
    await expect(kr.getMnemonic()).rejects.toThrow();
  });

  it('unlock rejects a wrong password and accepts the right one', async () => {
    const { storage } = fakeStorage();
    const kr = new WarrenKeyring(storage);
    await kr.create(PASSWORD);
    kr.lock();

    await expect(kr.unlock('wrong')).rejects.toBeInstanceOf(WarrenVaultError);
    await kr.unlock(PASSWORD);
    expect(kr.isUnlocked()).toBe(true);
  });

  it('rehydrates a fresh instance from the session-cached key without the password', async () => {
    const { storage } = fakeStorage();
    const first = new WarrenKeyring(storage);
    const mnemonic = await first.create(PASSWORD);

    // Simulate a service-worker restart: a brand new keyring over the same
    // storage. session survives a SW death (cleared only on browser close).
    const revived = new WarrenKeyring(storage);
    expect(revived.isUnlocked()).toBe(false);
    const ok = await revived.rehydrate();

    expect(ok).toBe(true);
    expect(revived.isUnlocked()).toBe(true);
    expect(await revived.getMnemonic()).toBe(mnemonic);
  });

  it('rehydrate returns false when the session cache is gone (browser was closed)', async () => {
    const { storage, session } = fakeStorage();
    await new WarrenKeyring(storage).create(PASSWORD);
    session.clear(); // browser restart wipes session storage

    const revived = new WarrenKeyring(storage);
    expect(await revived.rehydrate()).toBe(false);
    expect(revived.isUnlocked()).toBe(false);
  });
});

describe('WarrenKeyring.destroy', () => {
  it('erases the vault and the session cache and locks the keyring', async () => {
    const { storage, local, session } = fakeStorage();
    const kr = new WarrenKeyring(storage);
    await kr.create(PASSWORD);

    await kr.destroy();

    expect(kr.isUnlocked()).toBe(false);
    expect(local.size).toBe(0);
    expect(session.size).toBe(0);
    expect(await kr.hasVault()).toBe(false);
    // A destroyed vault cannot be rehydrated by a future instance.
    expect(await new WarrenKeyring(storage).rehydrate()).toBe(false);
  });
});
