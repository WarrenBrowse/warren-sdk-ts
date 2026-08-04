import { bytesToHex, randomBytes } from '@noble/hashes/utils';

/**
 * Generates a fresh request nonce: 16 random bytes as 32 lowercase hex chars.
 *
 * Matches the Warren wire contract (16-byte nonce). `randomBytes` is backed by
 * the platform CSPRNG (`crypto.getRandomValues` in browsers, `node:crypto` in
 * Node), so this is isomorphic.
 */
export function randomNonceHex(): string {
  return bytesToHex(randomBytes(16));
}
