import { blake2b } from '@noble/hashes/blake2b';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import { base58 } from '@scure/base';

/**
 * Warren SS58 network prefix. The `wb...` address space.
 *
 * Frozen by `vectors/identity.json`. Identical to
 * `@polkadot/util-crypto` `encodeAddress(pubkey, 13295)`.
 */
export const WARREN_SS58_PREFIX = 13295;

/** Domain-separation prefix for the SS58 checksum (the ASCII string `SS58PRE`). */
const SS58PRE = utf8ToBytes('SS58PRE');

/**
 * Encodes the two-byte SS58 network prefix for an identifier in the
 * `[64, 16383]` range, per the Substrate SS58 specification.
 */
function encodePrefix(prefix: number): Uint8Array {
  if (prefix < 0 || prefix > 16383) {
    throw new RangeError('SS58 prefix out of range');
  }
  if (prefix < 64) {
    return Uint8Array.of(prefix);
  }
  const first = ((prefix & 0b0000_0000_1111_1100) >> 2) | 0b0100_0000;
  const second = (prefix >> 8) | ((prefix & 0b0000_0000_0000_0011) << 6);
  return Uint8Array.of(first, second);
}

/**
 * Encodes a 32-byte Ed25519 public key as a Warren SS58 address (`wb...`).
 *
 * The checksum is the first two bytes of `blake2b-512("SS58PRE" || prefix || pubkey)`.
 */
export function encodeAddress(publicKey: Uint8Array, prefix: number = WARREN_SS58_PREFIX): string {
  if (publicKey.length !== 32) {
    throw new RangeError('Warren public key must be 32 bytes');
  }
  const payload = concatBytes(encodePrefix(prefix), publicKey);
  const checksum = blake2b(concatBytes(SS58PRE, payload), { dkLen: 64 }).subarray(0, 2);
  return base58.encode(concatBytes(payload, checksum));
}

/**
 * Decodes a Warren SS58 address (`wb...`) back to its 32-byte Ed25519 public
 * key, verifying the network prefix and the Blake2b checksum.
 *
 * @throws RangeError if the address is malformed, has the wrong prefix, or fails
 * the checksum.
 */
export function decodeAddress(address: string, prefix: number = WARREN_SS58_PREFIX): Uint8Array {
  const data = base58.decode(address);
  const firstByte = data[0];
  if (firstByte === undefined) {
    throw new RangeError('empty SS58 address');
  }
  // The high bit pattern of the first byte signals a one- or two-byte prefix.
  const prefixLen = (firstByte & 0b0100_0000) !== 0 ? 2 : 1;
  if (data.length !== prefixLen + 34) {
    throw new RangeError('invalid SS58 address length');
  }

  let actualPrefix: number;
  if (prefixLen === 1) {
    actualPrefix = firstByte;
  } else {
    const second = data[1] as number;
    const high = second & 0b0011_1111;
    const low2 = second >> 6;
    const mid = firstByte & 0b0011_1111;
    actualPrefix = (high << 8) | ((mid << 2) | low2);
  }
  if (actualPrefix !== prefix) {
    throw new RangeError('unexpected SS58 network prefix');
  }

  const publicKey = data.subarray(prefixLen, prefixLen + 32);
  const checksum = data.subarray(prefixLen + 32, prefixLen + 34);
  const payload = data.subarray(0, prefixLen + 32);
  const expected = blake2b(concatBytes(SS58PRE, payload), { dkLen: 64 }).subarray(0, 2);
  if (checksum[0] !== expected[0] || checksum[1] !== expected[1]) {
    throw new RangeError('bad SS58 checksum');
  }
  return Uint8Array.from(publicKey);
}
