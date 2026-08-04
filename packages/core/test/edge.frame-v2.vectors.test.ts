import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  WARREN_HPKE_VERSION_V2,
  type WarrenMultihopFrameV2,
  decodeMultihopFrameV2,
  encodeMultihopFrameV2,
} from '../src/edge/frame-v2.js';
import {
  WARREN_HPKE_VERSION,
  decodeMultihopFrame,
  encodeMultihopFrame,
} from '../src/edge/frame.js';

/**
 * Shared cross-implementation golden vector for the `/v2` post-quantum multihop
 * frame (`warren-vectors/multihop_frame_v2.json`): postcard layout
 * `version u8 | exit_id[16] | epoch varint | seq varint | encapsulated_key[32] |
 * pq_ct(len+bytes) | aead_tag[16] | ciphertext(len+bytes)`. Encoding these exact
 * inputs must reproduce the frozen bytes; decoding them must round-trip.
 */
const vectorsPath = fileURLToPath(
  new URL('../../../vectors/multihop_frame_v2.json', import.meta.url),
);
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8'));

interface FrameVector {
  exit_id_hex: string;
  epoch: number;
  seq: number;
  encapsulated_key_hex: string;
  pq_ct_hex: string;
  aead_tag_hex: string;
  ciphertext_hex: string;
  bytes_hex: string;
}

function frameFromVector(v: FrameVector): WarrenMultihopFrameV2 {
  return {
    version: WARREN_HPKE_VERSION_V2,
    exitId: hexToBytes(v.exit_id_hex),
    epoch: v.epoch,
    seq: BigInt(v.seq),
    encapsulatedKey: hexToBytes(v.encapsulated_key_hex),
    pqCt: hexToBytes(v.pq_ct_hex),
    aeadTag: hexToBytes(v.aead_tag_hex),
    ciphertext: hexToBytes(v.ciphertext_hex),
  };
}

describe('/v2 multihop frame golden vector (postcard, X-Wing seal)', () => {
  it('pins the /v2 version byte to 0x02', () => {
    expect(WARREN_HPKE_VERSION_V2).toBe(2);
    expect(vector.version).toBe(2);
  });

  it.each(vector.vectors.map((v: FrameVector, i: number) => [i, v]))(
    'encodes vector[%i] to the frozen bytes and decodes back',
    (_i, v: FrameVector) => {
      const encoded = encodeMultihopFrameV2(frameFromVector(v));
      expect(bytesToHex(encoded)).toBe(v.bytes_hex);

      const decoded = decodeMultihopFrameV2(hexToBytes(v.bytes_hex));
      expect(decoded.version).toBe(2);
      expect(bytesToHex(decoded.exitId)).toBe(v.exit_id_hex);
      expect(decoded.epoch).toBe(v.epoch);
      expect(decoded.seq).toBe(BigInt(v.seq));
      expect(bytesToHex(decoded.encapsulatedKey)).toBe(v.encapsulated_key_hex);
      expect(bytesToHex(decoded.pqCt)).toBe(v.pq_ct_hex);
      expect(bytesToHex(decoded.aeadTag)).toBe(v.aead_tag_hex);
      expect(bytesToHex(decoded.ciphertext)).toBe(v.ciphertext_hex);
    },
  );

  it('rejects trailing bytes after a valid /v2 frame', () => {
    const bytes = hexToBytes(vector.vectors[1].bytes_hex);
    const withExtra = new Uint8Array(bytes.length + 1);
    withExtra.set(bytes, 0);
    withExtra[bytes.length] = 0xff;
    expect(() => decodeMultihopFrameV2(withExtra)).toThrow();
  });

  it('never cross-decodes with /v1: a /v2 decoder rejects a /v1 frame and vice-versa', () => {
    // A /v1 frame (version 0x01) fed to the /v2 decoder must be refused.
    const v1Bytes = encodeMultihopFrame({
      version: WARREN_HPKE_VERSION,
      exitId: new Uint8Array(16).fill(0xa1),
      epoch: 0,
      seq: 0n,
      encapsulatedKey: new Uint8Array(32).fill(0x02),
      aeadTag: new Uint8Array(16).fill(0x03),
      ciphertext: new Uint8Array([1, 2, 3]),
    });
    expect(() => decodeMultihopFrameV2(v1Bytes)).toThrow();

    // A /v2 frame fed to the /v1 decoder must be refused.
    const v2Bytes = hexToBytes(vector.vectors[1].bytes_hex);
    expect(() => decodeMultihopFrame(v2Bytes)).toThrow();
  });
});
