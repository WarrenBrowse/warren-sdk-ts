import {
  mnemonicToSeedSync,
  generateMnemonic as scureGenerateMnemonic,
  validateMnemonic,
} from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

/**
 * A BIP39 mnemonic that failed validation (unknown word, wrong word count, or
 * bad checksum). The message never contains the phrase itself.
 */
export class WarrenMnemonicError extends Error {
  constructor() {
    super('invalid BIP39 mnemonic (unknown word, word count, or checksum)');
    this.name = 'WarrenMnemonicError';
  }
}

/**
 * Generates a fresh 12-word English BIP39 mnemonic (128 bits of entropy).
 *
 * 12 words is the Warren standard. The returned phrase is the sole secret of a
 * non-custodial identity; the caller must store it securely and never log it.
 */
export function generateMnemonic(): string {
  return scureGenerateMnemonic(wordlist, 128);
}

/**
 * Converts a BIP39 mnemonic (English wordlist) to the Warren 32-byte seed.
 *
 * A BIP39 seed is natively 64 bytes (PBKDF2-SHA512, empty passphrase). Warren
 * keeps only the first 32 and feeds them to the HKDF key derivation. The empty
 * passphrase is intentional: the mnemonic alone reproduces the identity.
 *
 * The returned bytes are secret material; the caller is responsible for not
 * logging or persisting them in clear.
 *
 * @throws WarrenMnemonicError if the phrase fails BIP39 validation. Full
 * validation (wordlist membership + checksum) is load-bearing: deriving from a
 * mistyped phrase would silently produce a different identity than the one the
 * user backed up, where the Rust SDK rejects it.
 */
export function seedFromMnemonic(mnemonic: string): Uint8Array {
  const normalized = mnemonic.normalize('NFKD');
  if (!validateMnemonic(normalized, wordlist)) {
    throw new WarrenMnemonicError();
  }
  const seed64 = mnemonicToSeedSync(normalized, '');
  // Copy the 32 bytes out and zeroize the full 64-byte seed: a subarray would
  // keep the whole secret alive in the shared backing buffer.
  const seed32 = seed64.slice(0, 32);
  seed64.fill(0);
  return seed32;
}
