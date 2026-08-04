/**
 * The Warren `/v2` post-quantum multi-hop datagram frame, carrying the X-Wing
 * (X25519 + ML-KEM-768) hybrid seal. Byte-for-byte compatible with the Rust
 * `WarrenMultihopFrameV2` (`warrenguard-multihop/wire_format_v2.rs`), pinned by
 * the shared golden vector `vectors/multihop_frame_v2.json`.
 *
 * A strict, versioned SIBLING of the `/v1` {@link WarrenMultihopFrame}: its own
 * version byte {@link WARREN_HPKE_VERSION_V2} (`0x02`), one extra `pq_ct` field,
 * and it never cross-decodes with `/v1` (a `/v1` decoder rejects `0x02` and this
 * decoder rejects `0x01`). The `/v1` frame is frozen and untouched.
 *
 * postcard serializes struct fields in declaration order:
 *   version u8 | exit_id [u8;16] raw | epoch u32 LEB128 | seq u64 LEB128 |
 *   encapsulated_key [u8;32] raw | pq_ct (LEB128 length prefix + raw bytes) |
 *   aead_tag [u8;16] raw | ciphertext (LEB128 length prefix + raw bytes)
 *
 * `encapsulated_key` keeps the `/v1` position and role: it carries the X25519
 * ephemeral public `ct_X`, so that 32-byte portion of the wire is shaped exactly
 * like `/v1`. `pq_ct` carries the 1088-byte ML-KEM ciphertext `ct_M` on the
 * setup/rekey frame and MAY be empty on a steady-state data frame (the receiver
 * already holds the epoch session), so no new per-packet tell is introduced.
 */

import { decodeLeb128, encodeLeb128 } from './varint.js';

/** Frame wire version byte for `/v2`. Must equal the Rust `WARREN_HPKE_VERSION_V2`. */
export const WARREN_HPKE_VERSION_V2 = 2;

const EXIT_ID_LEN = 16;
const ENCAPSULATED_KEY_LEN = 32;
const AEAD_TAG_LEN = 16;
/** Defensive upper bound on a decoded frame, mirroring the Rust `MAX_FRAME_SIZE`. */
const MAX_FRAME_SIZE = 65536;

/** A decoded/constructed Warren `/v2` post-quantum multi-hop frame. */
export interface WarrenMultihopFrameV2 {
  /** Wire version byte ({@link WARREN_HPKE_VERSION_V2} for `/v2`). */
  version: number;
  /** 16-byte exit routing tag, bound into the PQ AAD. */
  exitId: Uint8Array;
  /** X-Wing rekey epoch counter. */
  epoch: number;
  /** Per-session monotonic sequence number. */
  seq: bigint;
  /** 32-byte X25519 ephemeral public (`ct_X`), the X25519 half of the X-Wing
   * ciphertext; same field position/role as the `/v1` `encapsulated_key`. */
  encapsulatedKey: Uint8Array;
  /** ML-KEM-768 ciphertext (`ct_M`, 1088 bytes) on a setup/rekey frame; empty on
   * a steady-state data frame. The full X-Wing ciphertext is `pqCt || encapsulatedKey`. */
  pqCt: Uint8Array;
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
 * Encodes a {@link WarrenMultihopFrameV2} to its postcard wire bytes.
 *
 * @throws RangeError if any fixed-length field has the wrong size or `seq` is
 * negative.
 */
export function encodeMultihopFrameV2(frame: WarrenMultihopFrameV2): Uint8Array {
  expectLen(frame.exitId, EXIT_ID_LEN, 'exitId');
  expectLen(frame.encapsulatedKey, ENCAPSULATED_KEY_LEN, 'encapsulatedKey');
  expectLen(frame.aeadTag, AEAD_TAG_LEN, 'aeadTag');

  const epoch = encodeLeb128(frame.epoch);
  const seq = encodeLeb128(frame.seq);
  const pqCtLen = encodeLeb128(frame.pqCt.length);
  const ctLen = encodeLeb128(frame.ciphertext.length);

  const out = new Uint8Array(
    1 +
      EXIT_ID_LEN +
      epoch.length +
      seq.length +
      ENCAPSULATED_KEY_LEN +
      pqCtLen.length +
      frame.pqCt.length +
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
  out.set(pqCtLen, o);
  o += pqCtLen.length;
  out.set(frame.pqCt, o);
  o += frame.pqCt.length;
  out.set(frame.aeadTag, o);
  o += AEAD_TAG_LEN;
  out.set(ctLen, o);
  o += ctLen.length;
  out.set(frame.ciphertext, o);
  return out;
}

/**
 * Decodes a postcard-encoded {@link WarrenMultihopFrameV2}. Rejects trailing
 * bytes (frame malleability) and an unexpected version, mirroring the Rust
 * `WarrenMultihopFrameV2::decode`. A `/v1` frame (version `0x01`) is refused
 * here, and this frame's `0x02` is refused by the `/v1` decoder.
 *
 * @throws RangeError on truncation, trailing bytes, an oversize frame, or a
 * version mismatch.
 */
export function decodeMultihopFrameV2(bytes: Uint8Array): WarrenMultihopFrameV2 {
  if (bytes.length > MAX_FRAME_SIZE) {
    throw new RangeError('frame exceeds the maximum size');
  }
  let o = 0;
  const need = (n: number, what: string): void => {
    if (o + n > bytes.length) {
      throw new RangeError(`truncated frame: need ${n} more bytes for ${what}`);
    }
  };
  need(1, 'version');
  const version = bytes[o] ?? 0;
  o += 1;
  if (version !== WARREN_HPKE_VERSION_V2) {
    throw new RangeError(`unsupported /v2 frame version ${version}`);
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
  const pqCtLenDec = decodeLeb128(bytes.subarray(o));
  o += pqCtLenDec.length;
  const pqCtLen = Number(pqCtLenDec.value);
  need(pqCtLen, 'pq_ct');
  const pqCt = bytes.slice(o, o + pqCtLen);
  o += pqCtLen;
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
    pqCt,
    aeadTag,
    ciphertext,
  };
}
