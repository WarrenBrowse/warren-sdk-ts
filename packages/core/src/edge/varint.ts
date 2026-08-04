/**
 * postcard variable-length integer encoding (LEB128), as used by the Rust
 * `postcard` crate to serialize the `u32`/`u64` fields of a
 * {@link WarrenMultihopFrame}.
 *
 * IMPORTANT: this is NOT the QUIC/HTTP3 varint (that is a 2-bit-prefix,
 * big-endian scheme used by the WebTransport framing layer). postcard uses
 * unsigned LEB128: 7 payload bits per byte, least-significant group first, the
 * high bit set on every byte except the last. Confusing the two is a silent
 * wire break, so the two encoders live in separate modules on purpose.
 */

/** Encodes a non-negative integer as postcard/LEB128 bytes. */
export function encodeLeb128(value: number | bigint): Uint8Array {
  let v = typeof value === 'bigint' ? value : BigInt(value);
  if (v < 0n) {
    throw new RangeError('LEB128 encodes non-negative integers only');
  }
  const out: number[] = [];
  // Emit 7-bit groups low-to-high; set the continuation bit on all but the last.
  for (;;) {
    const byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v === 0n) {
      out.push(byte);
      break;
    }
    out.push(byte | 0x80);
  }
  return Uint8Array.from(out);
}

/** A decoded LEB128 value and the number of bytes it consumed. */
export interface Leb128Decoded {
  /** The decoded value as a bigint (fits u64). */
  value: bigint;
  /** Bytes consumed from the input. */
  length: number;
}

/**
 * Decodes one postcard/LEB128 integer from the front of `input`.
 *
 * @throws RangeError if the input ends mid-integer or the value exceeds 64 bits
 * (a 10th continuation byte), which a well-formed `u64` frame field never does.
 */
export function decodeLeb128(input: Uint8Array): Leb128Decoded {
  let value = 0n;
  let shift = 0n;
  let length = 0;
  for (const byte of input) {
    value |= BigInt(byte & 0x7f) << shift;
    length += 1;
    if ((byte & 0x80) === 0) {
      return { value, length };
    }
    shift += 7n;
    if (shift >= 70n) {
      throw new RangeError('LEB128 integer exceeds 64 bits');
    }
  }
  throw new RangeError('truncated LEB128 integer');
}
