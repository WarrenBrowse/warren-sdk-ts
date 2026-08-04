import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bytesToHex } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import { decodeAddress, encodeAddress, keyPairFromSeed } from '../src/index.js';

const vectorsPath = fileURLToPath(new URL('../../../vectors/identity.json', import.meta.url));
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));

describe('decodeAddress (SS58 round-trip)', () => {
  it('decodes each address back to its pubkey', () => {
    for (const [pubkeyHex, address] of vectors.ss58.vectors) {
      expect(bytesToHex(decodeAddress(address))).toBe(pubkeyHex);
    }
  });

  it('rejects a corrupted checksum', () => {
    const [, address] = vectors.ss58.vectors[0];
    const broken = `${address.slice(0, -1)}${address.at(-1) === 'A' ? 'B' : 'A'}`;
    expect(() => decodeAddress(broken)).toThrow();
  });

  it('round-trips a re-encoded pubkey', () => {
    const [pubkeyHex, address] = vectors.ss58.vectors[1];
    expect(encodeAddress(decodeAddress(address))).toBe(address);
    expect(bytesToHex(decodeAddress(address))).toBe(pubkeyHex);
  });

  it('rejects an address with the wrong network prefix', () => {
    const [pubkeyHex] = vectors.ss58.vectors[0];
    const foreign = encodeAddress(decodeAddress(vectors.ss58.vectors[0][1]), 42);
    expect(foreign.startsWith('wb')).toBe(false);
    expect(() => decodeAddress(foreign)).toThrow(/prefix/);
    // Sanity: the same payload under the Warren prefix still decodes.
    expect(bytesToHex(decodeAddress(vectors.ss58.vectors[0][1]))).toBe(pubkeyHex);
  });

  it('rejects an empty address', () => {
    expect(() => decodeAddress('')).toThrow(RangeError);
  });

  it('rejects an address of the wrong length', () => {
    // A valid base58 string that is far too short to hold prefix + key + checksum.
    expect(() => decodeAddress('wb')).toThrow(/length/);
  });
});

describe('input validation', () => {
  it('encodeAddress rejects a non-32-byte public key', () => {
    expect(() => encodeAddress(new Uint8Array(31))).toThrow(RangeError);
  });

  it('encodeAddress rejects an out-of-range prefix', () => {
    expect(() => encodeAddress(new Uint8Array(32), 16384)).toThrow(RangeError);
  });

  it('keyPairFromSeed rejects a non-32-byte seed', () => {
    expect(() => keyPairFromSeed(new Uint8Array(16))).toThrow(RangeError);
  });
});
