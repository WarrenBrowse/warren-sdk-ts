/**
 * The Warren multi-hop datagram frame (`frame/v1`), the wire unit a browser
 * EdgeConnect client tunnels through a WebTransport session to reach a Warren
 * exit. Byte-for-byte compatible with the Rust `WarrenMultihopFrame`
 * (`warrenguard-multihop`), pinned by the shared golden vector
 * `vectors/multihop_frame.json`.
 *
 * postcard serializes struct fields in declaration order:
 *   version u8 | exit_id [u8;16] raw | epoch u32 LEB128 | seq u64 LEB128 |
 *   encapsulated_key [u8;32] raw | aead_tag [u8;16] raw |
 *   ciphertext (LEB128 length prefix + raw bytes)
 *
 * Fixed-size arrays carry NO length prefix; only the trailing `Vec<u8>`
 * ciphertext does.
 */

import { decodeLeb128, encodeLeb128 } from './varint.js';

/** Frame wire version byte. Must equal the Rust `WARREN_HPKE_VERSION_V1`. */
export const WARREN_HPKE_VERSION = 1;

const EXIT_ID_LEN = 16;
const ENCAPSULATED_KEY_LEN = 32;
const AEAD_TAG_LEN = 16;

/** A decoded/constructed Warren multi-hop frame. */
export interface WarrenMultihopFrame {
  /** Wire version byte ({@link WARREN_HPKE_VERSION} for `/v1`). */
  version: number;
  /** 16-byte exit routing tag. */
  exitId: Uint8Array;
  /** HPKE rekey epoch counter. */
  epoch: number;
  /** Per-session monotonic sequence number. */
  seq: bigint;
  /** 32-byte ephemeral X25519 public key (HPKE KEM output). */
  encapsulatedKey: Uint8Array;
  /** 16-byte detached ChaCha20-Poly1305 tag. */
  aeadTag: Uint8Array;
  /** AEAD ciphertext (same length as the sealed plaintext). */
  ciphertext: Uint8Array;
}

function expectLen(bytes: Uint8Array, len: number, field: string): void {
  if (bytes.length !== len) {
    throw new RangeError(`${field} must be ${len} bytes, got ${bytes.length}`);
  }
}

/**
 * Encodes a {@link WarrenMultihopFrame} to its postcard wire bytes.
 *
 * @throws RangeError if any fixed-length field has the wrong size or `seq` is
 * negative.
 */
export function encodeMultihopFrame(frame: WarrenMultihopFrame): Uint8Array {
  expectLen(frame.exitId, EXIT_ID_LEN, 'exitId');
  expectLen(frame.encapsulatedKey, ENCAPSULATED_KEY_LEN, 'encapsulatedKey');
  expectLen(frame.aeadTag, AEAD_TAG_LEN, 'aeadTag');

  const epoch = encodeLeb128(frame.epoch);
  const seq = encodeLeb128(frame.seq);
  const ctLen = encodeLeb128(frame.ciphertext.length);

  const out = new Uint8Array(
    1 +
      EXIT_ID_LEN +
      epoch.length +
      seq.length +
      ENCAPSULATED_KEY_LEN +
      AEAD_TAG_LEN +
      ctLen.length +
      frame.ciphertext.length,
  );
  let o = 0;
  out[o++] = frame.version;
  out.set(frame.exitId, o);
  o += EXIT_ID_LEN;
  out.set(epoch, o);
  o += epoch.length;
  out.set(seq, o);
  o += seq.length;
  out.set(frame.encapsulatedKey, o);
  o += ENCAPSULATED_KEY_LEN;
  out.set(frame.aeadTag, o);
  o += AEAD_TAG_LEN;
  out.set(ctLen, o);
  o += ctLen.length;
  out.set(frame.ciphertext, o);
  return out;
}

/**
 * Decodes a postcard-encoded {@link WarrenMultihopFrame}. Rejects trailing
 * bytes (frame malleability) and an unexpected version, mirroring the Rust
 * `WarrenMultihopFrame::decode`.
 *
 * @throws RangeError on truncation, trailing bytes, or a version mismatch.
 */
export function decodeMultihopFrame(bytes: Uint8Array): WarrenMultihopFrame {
  let o = 0;
  const need = (n: number, what: string): void => {
    if (o + n > bytes.length) {
      throw new RangeError(`truncated frame: need ${n} more bytes for ${what}`);
    }
  };
  need(1, 'version');
  const version = bytes[o] ?? 0;
  o += 1;
  if (version !== WARREN_HPKE_VERSION) {
    throw new RangeError(`unsupported frame version ${version}`);
  }
  need(EXIT_ID_LEN, 'exit_id');
  const exitId = bytes.slice(o, o + EXIT_ID_LEN);
  o += EXIT_ID_LEN;
  const epochDec = decodeLeb128(bytes.subarray(o));
  o += epochDec.length;
  const seqDec = decodeLeb128(bytes.subarray(o));
  o += seqDec.length;
  need(ENCAPSULATED_KEY_LEN, 'encapsulated_key');
  const encapsulatedKey = bytes.slice(o, o + ENCAPSULATED_KEY_LEN);
  o += ENCAPSULATED_KEY_LEN;
  need(AEAD_TAG_LEN, 'aead_tag');
  const aeadTag = bytes.slice(o, o + AEAD_TAG_LEN);
  o += AEAD_TAG_LEN;
  const ctLenDec = decodeLeb128(bytes.subarray(o));
  o += ctLenDec.length;
  const ctLen = Number(ctLenDec.value);
  need(ctLen, 'ciphertext');
  const ciphertext = bytes.slice(o, o + ctLen);
  o += ctLen;
  if (o !== bytes.length) {
    throw new RangeError('trailing bytes after frame');
  }
  return {
    version,
    exitId,
    epoch: Number(epochDec.value),
    seq: seqDec.value,
    encapsulatedKey,
    aeadTag,
    ciphertext,
  };
}
