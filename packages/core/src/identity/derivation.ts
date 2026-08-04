import { ed25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';

/**
 * Frozen HKDF parameters (`vectors/identity.json`). Any change is a wire-format
 * break that requires rotating the schema to `identity/v2`.
 */
const HKDF_SALT = utf8ToBytes('warren/identity/v1');
const HKDF_INFO = utf8ToBytes('vpn-node-key');

/** An Ed25519 keypair derived from a Warren 32-byte seed. */
export interface WarrenKeyPair {
  /** The 32-byte Ed25519 secret seed. Treat as secret; never log it. */
  readonly secretKey: Uint8Array;
  /** The 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;
}

/**
 * Derives the Warren Ed25519 keypair from a 32-byte seed.
 *
 * `seed32 -> HKDF-SHA256(salt = warren/identity/v1, info = vpn-node-key, len = 32)
 *  -> Ed25519`.
 */
export function keyPairFromSeed(seed32: Uint8Array): WarrenKeyPair {
  if (seed32.length !== 32) {
    throw new RangeError('Warren seed must be 32 bytes');
  }
  const secretKey = hkdf(sha256, seed32, HKDF_SALT, HKDF_INFO, 32);
  const publicKey = ed25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
}

/**
 * Zeroizes the keypair's secret key in place. Call when the pair is no longer
 * needed; any later signing attempt with it will produce garbage, not a leak.
 * JS cannot guarantee no copies exist, but this clears the long-lived buffer.
 */
export function wipeKeyPair(pair: WarrenKeyPair): void {
  pair.secretKey.fill(0);
}
