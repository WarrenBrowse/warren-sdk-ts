import { bytesToHex } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  decodeQuicVarint,
  decodeWtDatagram,
  encodeBidiStreamHeader,
  encodeQuicVarint,
  encodeUniStreamHeader,
  encodeWtDatagram,
  quarterStreamId,
} from '../src/edge/webtransport.js';

/**
 * These pin the exact WebTransport framing bytes the Rust
 * `warrenguard-edge::webtransport` module emits (its unit tests assert the same
 * golden bytes), so the browser client and the edge server stay wire-identical.
 */
describe('WebTransport framing (draft-02) golden bytes', () => {
  it('bidi stream header for session 4 is 0x40 0x41 0x04', () => {
    // The signal 0x41 (== 65 >= 64) is the TWO-byte QUIC varint 0x40 0x41, then
    // the single-byte session id 0x04 (the trap that pins draft-02 vs a naive
    // single 0x41 byte).
    expect(Array.from(encodeBidiStreamHeader(4))).toEqual([0x40, 0x41, 0x04]);
  });

  it('uni stream header for session 8 is 0x40 0x54 0x08', () => {
    expect(Array.from(encodeUniStreamHeader(8))).toEqual([0x40, 0x54, 0x08]);
  });

  it('quarter-stream-id divides the session id by four', () => {
    expect(quarterStreamId(0)).toBe(0n);
    expect(quarterStreamId(4)).toBe(1n);
    expect(quarterStreamId(8)).toBe(2n);
    expect(quarterStreamId(0xffff_fffc)).toBe(0x3fff_ffffn);
  });

  it('datagram for session 4 is the quarter-stream-id 0x01 then payload', () => {
    expect(Array.from(encodeWtDatagram(4, Uint8Array.from([0x44, 0x41, 0x54, 0x41])))).toEqual([
      0x01, 0x44, 0x41, 0x54, 0x41,
    ]);
  });

  it('datagram round-trips the quarter-stream-id and payload', () => {
    const dg = encodeWtDatagram(0x400, Uint8Array.from([0, 1, 2, 3]));
    const dec = decodeWtDatagram(dg);
    expect(dec).not.toBeNull();
    expect(dec?.quarterStreamId).toBe(quarterStreamId(0x400));
    expect(bytesToHex(dec?.payload ?? new Uint8Array())).toBe('00010203');
  });
});

describe('QUIC varint (RFC 9000)', () => {
  it('round-trips the four length classes at their boundaries', () => {
    const cases: bigint[] = [
      0n,
      63n,
      64n,
      16383n,
      16384n,
      1073741823n,
      1073741824n,
      (1n << 62n) - 1n,
    ];
    for (const c of cases) {
      const enc = encodeQuicVarint(c);
      const dec = decodeQuicVarint(enc);
      expect(dec?.value).toBe(c);
      expect(dec?.length).toBe(enc.length);
    }
  });

  it('returns null on a truncated multi-byte varint', () => {
    // First byte announces a 2-byte varint but only one byte is present.
    expect(decodeQuicVarint(Uint8Array.from([0x40]))).toBeNull();
  });
});
