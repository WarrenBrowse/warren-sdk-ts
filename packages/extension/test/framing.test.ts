import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import { NativeFrameDecoder, encodeNativeFrame } from '../src/host/framing.js';

describe('native messaging framing', () => {
  it('encodes a message as a 4-byte little-endian length prefix plus UTF-8 JSON', () => {
    const frame = encodeNativeFrame({ a: 1 });
    const json = Buffer.from(JSON.stringify({ a: 1 }), 'utf8');
    expect(frame.readUInt32LE(0)).toBe(json.length);
    expect(frame.subarray(4).toString('utf8')).toBe('{"a":1}');
  });

  it('round-trips through the decoder, including split and concatenated frames', () => {
    const decoder = new NativeFrameDecoder();
    const one = encodeNativeFrame({ type: 'hello' });
    const two = encodeNativeFrame({ type: 'status' });
    expect(decoder.push(one.subarray(0, 3))).toEqual([]);
    expect(decoder.push(Buffer.concat([one.subarray(3), two]))).toEqual([
      { type: 'hello' },
      { type: 'status' },
    ]);
  });

  it('rejects a frame above the 1 MB host-to-browser cap', () => {
    expect(() => encodeNativeFrame({ blob: 'x'.repeat(1024 * 1024) })).toThrow(RangeError);
    const decoder = new NativeFrameDecoder();
    const absurd = Buffer.alloc(4);
    absurd.writeUInt32LE(64 * 1024 * 1024, 0);
    expect(() => decoder.push(absurd)).toThrow(RangeError);
  });
});
