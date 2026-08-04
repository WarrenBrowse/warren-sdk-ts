import { describe, expect, it } from 'vitest';
import {
  WarrenVaultError,
  decryptMnemonic,
  deriveVaultKey,
  encryptMnemonic,
  exportVaultKey,
  importVaultKey,
} from '../src/index.js';

const MNEMONIC = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const PASSWORD = 'correct horse battery staple';

// PBKDF2 at 900k iterations is intentionally slow; keep the suite lean.
describe('WarrenVault', () => {
  it('round-trips a mnemonic through encrypt/decrypt with the right password', async () => {
    const blob = await encryptMnemonic(MNEMONIC, PASSWORD);
    expect(await decryptMnemonic(blob, PASSWORD)).toBe(MNEMONIC);
  });

  it('produces a self-describing JSON blob with the KDF and cipher parameters', async () => {
    const blob = JSON.parse(await encryptMnemonic(MNEMONIC, PASSWORD));
    expect(blob.v).toBe(1);
    expect(blob.kdf).toMatchObject({ name: 'PBKDF2', hash: 'SHA-256' });
    expect(blob.kdf.iterations).toBeGreaterThanOrEqual(900000);
    expect(blob.cipher.name).toBe('AES-GCM');
    // Salt, IV and ciphertext are present and base64; the mnemonic never appears.
    expect(typeof blob.kdf.salt).toBe('string');
    expect(typeof blob.cipher.iv).toBe('string');
    expect(typeof blob.ct).toBe('string');
    expect(await encryptMnemonic(MNEMONIC, PASSWORD)).not.toBe(
      await encryptMnemonic(MNEMONIC, PASSWORD),
    );
  });

  it('rejects a wrong password with a typed error (AES-GCM auth failure)', async () => {
    const blob = await encryptMnemonic(MNEMONIC, PASSWORD);
    await expect(decryptMnemonic(blob, 'wrong password')).rejects.toBeInstanceOf(WarrenVaultError);
  });

  it('rejects a tampered ciphertext', async () => {
    const blob = JSON.parse(await encryptMnemonic(MNEMONIC, PASSWORD));
    // Flip one base64 char in the ciphertext.
    blob.ct = `${blob.ct.slice(0, -2)}${blob.ct.at(-2) === 'A' ? 'B' : 'A'}=`;
    await expect(decryptMnemonic(JSON.stringify(blob), PASSWORD)).rejects.toBeInstanceOf(
      WarrenVaultError,
    );
  });

  it('the vault error message never contains the mnemonic or the password', async () => {
    const blob = await encryptMnemonic(MNEMONIC, PASSWORD);
    const err = await decryptMnemonic(blob, 'nope').catch((e) => e as Error);
    expect(err.message).not.toContain('legal');
    expect(err.message).not.toContain('nope');
  });

  it('caches a derived key across the storage.session boundary via export/import', async () => {
    // Mirrors MetaMask cacheEncryptionKey: derive once, export the CryptoKey to
    // JWK for storage.session, re-import on service-worker wake, decrypt without
    // re-deriving from the password.
    const blob = JSON.parse(await encryptMnemonic(MNEMONIC, PASSWORD));
    const derived = await deriveVaultKey(PASSWORD, blob.kdf.salt, blob.kdf.iterations);
    const jwk = await exportVaultKey(derived.key);
    const reimported = await importVaultKey(jwk);
    // Decrypt using the re-imported key path.
    const plain = await decryptMnemonic(JSON.stringify(blob), { key: reimported });
    expect(plain).toBe(MNEMONIC);
  });
});
