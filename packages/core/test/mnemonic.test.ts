import { describe, expect, it } from 'vitest';
import {
  WarrenMnemonicError,
  encodeAddress,
  generateMnemonic,
  keyPairFromSeed,
  seedFromMnemonic,
  wipeKeyPair,
} from '../src/index.js';

describe('generateMnemonic', () => {
  it('produces a valid, unique 12-word mnemonic that derives a wb... address', () => {
    const phrase = generateMnemonic();
    expect(phrase.split(' ')).toHaveLength(12);
    expect(generateMnemonic()).not.toBe(phrase);
    const address = encodeAddress(keyPairFromSeed(seedFromMnemonic(phrase)).publicKey);
    expect(address).toMatch(/^wb/);
  });

  it('seedFromMnemonic rejects an invalid phrase', () => {
    expect(() => seedFromMnemonic('clearly not a valid bip39 mnemonic phrase nope nope')).toThrow(
      WarrenMnemonicError,
    );
  });

  it('seedFromMnemonic rejects 12 valid words with a bad checksum', () => {
    // Valid wordlist words and word count; only the checksum is wrong. A silent
    // pass here would derive a different identity than the one the user backed up.
    expect(() => seedFromMnemonic('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo')).toThrow(
      WarrenMnemonicError,
    );
  });

  it('seedFromMnemonic rejects a mistyped word', () => {
    expect(() =>
      seedFromMnemonic(
        'legal winner thank year wave sausage worth useful legal winner thank yellowx',
      ),
    ).toThrow(WarrenMnemonicError);
  });

  it('wipeKeyPair zeroizes the secret key in place', () => {
    const pair = keyPairFromSeed(seedFromMnemonic(generateMnemonic()));
    expect(pair.secretKey.some((b) => b !== 0)).toBe(true);
    wipeKeyPair(pair);
    expect(pair.secretKey.every((b) => b === 0)).toBe(true);
  });

  it('mnemonic error message never contains the phrase', () => {
    let err: unknown;
    try {
      seedFromMnemonic('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo');
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(WarrenMnemonicError);
    expect((err as Error).message).not.toContain('zoo');
  });
});
