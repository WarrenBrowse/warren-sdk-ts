/**
 * Password-encrypted mnemonic vault (the wallet at rest).
 *
 * A browser extension's isolated context is the standard place to keep a
 * signing key, exactly as MetaMask/Phantom/Rabby do: the mnemonic is encrypted
 * with a key derived from the user's password and only ever decrypted in
 * memory. This module is the crypto core, isomorphic (WebCrypto on Node >= 20
 * and every browser). Storage, unlock lifetime and auto-lock are the caller's
 * concern.
 *
 * Parameters match current wallet practice: PBKDF2-HMAC-SHA256 at 900k
 * iterations (OWASP 2025 floor is 600k) and AES-256-GCM (authenticated, so a
 * wrong password or a tampered blob fails loudly). The blob records its own
 * KDF/cipher parameters so they can be raised later without a schema break.
 */

const webcrypto: Crypto = globalThis.crypto;

/** Current KDF iteration count. Raise freely: old blobs decrypt with their own recorded value. */
export const VAULT_ITERATIONS = 900_000;

/** A vault operation that failed (wrong password, tampered or malformed blob). */
export class WarrenVaultError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'WarrenVaultError';
  }
}

/** The self-describing on-disk vault shape (all binary fields base64). */
interface VaultBlob {
  v: 1;
  kdf: { name: 'PBKDF2'; hash: 'SHA-256'; iterations: number; salt: string };
  cipher: { name: 'AES-GCM'; iv: string };
  ct: string;
}

/** A derived vault key plus the KDF parameters that produced it. */
export interface DerivedVaultKey {
  key: CryptoKey;
  saltB64: string;
  iterations: number;
}

function toB64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromB64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Derives the AES-GCM vault key from a password. Pass an existing salt (base64)
 * to reproduce the key of an existing vault; omit it to mint a fresh vault.
 */
export async function deriveVaultKey(
  password: string,
  saltB64?: string,
  iterations: number = VAULT_ITERATIONS,
): Promise<DerivedVaultKey> {
  const salt = saltB64 ? fromB64(saltB64) : webcrypto.getRandomValues(new Uint8Array(32));
  const material = await webcrypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  const key = await webcrypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    // Extractable so the caller can cache it (JWK) in storage.session and
    // re-hydrate a keyring after the service worker is killed.
    true,
    ['encrypt', 'decrypt'],
  );
  return { key, saltB64: toB64(salt), iterations };
}

/** Exports a derived key to a JWK for in-memory session caching. */
export async function exportVaultKey(key: CryptoKey): Promise<JsonWebKey> {
  return webcrypto.subtle.exportKey('jwk', key);
}

/** Re-imports a cached JWK back into a usable AES-GCM key. */
export function importVaultKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return webcrypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}

/** Encrypts a mnemonic under a password, returning a self-describing JSON blob. */
export async function encryptMnemonic(mnemonic: string, password: string): Promise<string> {
  const derived = await deriveVaultKey(password);
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const plaintext = new TextEncoder().encode(mnemonic.normalize('NFKD'));
  const ct = new Uint8Array(
    await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      derived.key,
      plaintext as BufferSource,
    ),
  );
  plaintext.fill(0);
  const blob: VaultBlob = {
    v: 1,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: derived.iterations, salt: derived.saltB64 },
    cipher: { name: 'AES-GCM', iv: toB64(iv) },
    ct: toB64(ct),
  };
  return JSON.stringify(blob);
}

/**
 * Decrypts a vault blob. Pass the password, or `{ key }` with a cached derived
 * key (skips the expensive PBKDF2 derivation, for a service-worker rehydrate).
 *
 * @throws {WarrenVaultError} on a wrong password, a tampered ciphertext, or a
 * malformed blob. The message never contains secret material.
 */
export async function decryptMnemonic(
  blobJson: string,
  secret: string | { key: CryptoKey },
): Promise<string> {
  let blob: VaultBlob;
  try {
    blob = JSON.parse(blobJson) as VaultBlob;
    if (blob.v !== 1 || !blob.ct || !blob.cipher?.iv || !blob.kdf?.salt) {
      throw new Error('shape');
    }
  } catch (cause) {
    throw new WarrenVaultError('vault blob is malformed', { cause });
  }
  const key =
    typeof secret === 'string'
      ? (await deriveVaultKey(secret, blob.kdf.salt, blob.kdf.iterations)).key
      : secret.key;
  let plaintext: ArrayBuffer;
  try {
    plaintext = await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(blob.cipher.iv) as BufferSource },
      key,
      fromB64(blob.ct) as BufferSource,
    );
  } catch (cause) {
    // AES-GCM auth failure: wrong password or tampered blob, indistinguishable.
    throw new WarrenVaultError('vault could not be decrypted (wrong password or corrupt)', {
      cause,
    });
  }
  const bytes = new Uint8Array(plaintext);
  const mnemonic = new TextDecoder().decode(bytes);
  bytes.fill(0);
  return mnemonic;
}
