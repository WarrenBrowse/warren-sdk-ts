import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  type WarrenMultihopFrame,
  decodeMultihopFrame,
  encodeMultihopFrame,
} from '../src/edge/frame.js';
import { decodeLeb128, encodeLeb128 } from '../src/edge/varint.js';

/**
 * Shared cross-implementation golden vector (`warren-vectors/multihop_frame.json`),
 * the frozen wire contract every Warren SDK must reproduce. The TS EdgeConnect
 * frame encoder emitting these exact bytes proves byte-for-byte postcard
 * compatibility with the Rust `WarrenMultihopFrame`.
 */
const vectorsPath = fileURLToPath(new URL('../../../vectors/multihop_frame.json', import.meta.url));
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));

describe('WarrenMultihopFrame postcard golden vector', () => {
  for (const v of vectors.vectors) {
    it('reproduces the frozen wire bytes and round-trips', () => {
      const frame: WarrenMultihopFrame = {
        version: vectors.version,
        exitId: hexToBytes(v.exit_id_hex),
        epoch: v.epoch,
        seq: BigInt(v.seq),
        encapsulatedKey: hexToBytes(v.encapsulated_key_hex),
        aeadTag: hexToBytes(v.aead_tag_hex),
        ciphertext: hexToBytes(v.ciphertext_hex),
      };
      const encoded = encodeMultihopFrame(frame);
      expect(Buffer.from(encoded).toString('hex')).toBe(v.bytes_hex);

      const decoded = decodeMultihopFrame(hexToBytes(v.bytes_hex));
      expect(decoded.version).toBe(vectors.version);
      expect(Buffer.from(decoded.exitId).toString('hex')).toBe(v.exit_id_hex);
      expect(decoded.epoch).toBe(v.epoch);
      expect(decoded.seq).toBe(BigInt(v.seq));
      expect(Buffer.from(decoded.ciphertext).toString('hex')).toBe(v.ciphertext_hex);
    });
  }
});

describe('postcard LEB128 varint', () => {
  it('round-trips values spanning the u64 range', () => {
    // Includes multi-byte encodings the small golden-vector values (7, 42) do
    // not exercise, so a LEB128-vs-QUIC-varint confusion cannot hide here.
    const cases: bigint[] = [
      0n,
      1n,
      127n,
      128n,
      300n,
      16383n,
      16384n,
      4294967295n, // u32::MAX
      4294967296n,
      18446744073709551614n, // u64::MAX - 1
    ];
    for (const c of cases) {
      const enc = encodeLeb128(c);
      const dec = decodeLeb128(enc);
      expect(dec.value).toBe(c);
      expect(dec.length).toBe(enc.length);
    }
  });

  it('encodes 128 as 0x80 0x01 (two groups, low first)', () => {
    expect(Array.from(encodeLeb128(128))).toEqual([0x80, 0x01]);
  });

  it('rejects a truncated integer', () => {
    // A lone continuation byte (high bit set) never completes.
    expect(() => decodeLeb128(Uint8Array.from([0x80]))).toThrow();
  });
});
