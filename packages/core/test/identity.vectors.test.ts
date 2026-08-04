import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  canonicalMessage,
  encodeAddress,
  keyPairFromSeed,
  seedFromMnemonic,
  signRequest,
} from '../src/index.js';

/**
 * Replays the shared cross-implementation golden vectors. Every language SDK
 * MUST reproduce these byte-for-byte; this file is the TS half of that contract.
 */
const vectorsPath = fileURLToPath(new URL('../../../vectors/identity.json', import.meta.url));
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));

describe('identity golden vectors', () => {
  it('SS58: pubkey -> wb... address', () => {
    for (const [pubkeyHex, address] of vectors.ss58.vectors) {
      expect(encodeAddress(hexToBytes(pubkeyHex))).toBe(address);
    }
  });

  it('derivation: seed32 -> pubkey + address', () => {
    for (const v of vectors.derivation.vectors) {
      const { publicKey } = keyPairFromSeed(hexToBytes(v.seed_hex));
      expect(Buffer.from(publicKey).toString('hex')).toBe(v.pubkey_hex);
      expect(encodeAddress(publicKey)).toBe(v.address);
    }
  });

  it('bip39: mnemonic -> seed32 -> pubkey + address', () => {
    for (const v of vectors.bip39.vectors) {
      const seed = seedFromMnemonic(v.mnemonic);
      expect(Buffer.from(seed).toString('hex')).toBe(v.seed_hex);
      const { publicKey } = keyPairFromSeed(seed);
      expect(Buffer.from(publicKey).toString('hex')).toBe(v.pubkey_hex);
      expect(encodeAddress(publicKey)).toBe(v.address);
    }
  });

  it('canonical_message: byte-stable LF-joined string', () => {
    for (const v of vectors.canonical_message.vectors) {
      expect(canonicalMessage(v.method, v.path, v.timestamp, v.nonce_hex, v.body_hash_hex)).toBe(
        v.expected,
      );
    }
  });

  it('request_signature: deterministic Ed25519 over the canonical message', () => {
    for (const v of vectors.request_signature.vectors) {
      const sig = signRequest(
        hexToBytes(v.seed_hex),
        v.method,
        v.path,
        v.body_utf8,
        v.timestamp,
        v.nonce_hex,
      );
      expect(sig.pubkeySs58).toBe(v.pubkey_ss58);
      expect(sig.signatureHex).toBe(v.signature_hex);
    }
  });
});
