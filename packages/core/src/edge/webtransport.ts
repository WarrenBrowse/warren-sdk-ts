/**
 * WebTransport-over-HTTP/3 stream and datagram framing
 * (draft-ietf-webtrans-http3-02), the wire a browser speaks inside a
 * WebTransport session. Mirror of the Rust `warrenguard-edge::webtransport`
 * module, so the browser EdgeConnect client and the edge server agree
 * byte-for-byte.
 *
 * NOTE the two varint schemes in this file's world: the WebTransport
 * stream/datagram headers use the QUIC varint (2-bit length prefix, big-endian),
 * implemented here; the `WarrenMultihopFrame` fields use postcard LEB128 (see
 * `./varint.ts`). They are different encodings; do not confuse them.
 */

/** WebTransport bidirectional stream signal value (draft-02 section 4.2). */
export const WEBTRANSPORT_STREAM_BIDI = 0x41;
/** WebTransport unidirectional stream type (draft-02 section 4.1). */
export const WEBTRANSPORT_STREAM_UNI = 0x54;

/** Encodes a value as a QUIC variable-length integer (RFC 9000 section 16). */
export function encodeQuicVarint(value: number | bigint): Uint8Array {
  const v = typeof value === 'bigint' ? value : BigInt(value);
  if (v < 0n) {
    throw new RangeError('QUIC varint encodes non-negative integers only');
  }
  if (v < 1n << 6n) {
    return Uint8Array.from([Number(v)]);
  }
  if (v < 1n << 14n) {
    const n = Number(v);
    return Uint8Array.from([0x40 | (n >> 8), n & 0xff]);
  }
  if (v < 1n << 30n) {
    const n = Number(v);
    return Uint8Array.from([0x80 | (n >>> 24), (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
  }
  if (v < 1n << 62n) {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, v, false);
    out[0] = (out[0] ?? 0) | 0xc0;
    return out;
  }
  throw new RangeError('value exceeds the 62-bit QUIC varint maximum');
}

/** A decoded QUIC varint and the number of bytes it consumed. */
export interface QuicVarintDecoded {
  /** The decoded value as a bigint. */
  value: bigint;
  /** Bytes consumed from the input. */
  length: number;
}

/**
 * Decodes one QUIC varint from the front of `input`, or `null` if `input` does
 * not yet hold the full multi-byte encoding its 2-bit length prefix announces.
 */
export function decodeQuicVarint(input: Uint8Array): QuicVarintDecoded | null {
  const first = input[0];
  if (first === undefined) {
    return null;
  }
  const length = 1 << (first >> 6);
  if (input.length < length) {
    return null;
  }
  let value = BigInt(first & 0x3f);
  for (let i = 1; i < length; i++) {
    value = (value << 8n) | BigInt(input[i] ?? 0);
  }
  return { value, length };
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Encodes the header that opens a bidirectional WebTransport stream for
 * `sessionId`: the {@link WEBTRANSPORT_STREAM_BIDI} signal varint then the
 * Session ID varint. The WT stream body follows.
 */
export function encodeBidiStreamHeader(sessionId: number | bigint): Uint8Array {
  return concatBytes(encodeQuicVarint(WEBTRANSPORT_STREAM_BIDI), encodeQuicVarint(sessionId));
}

/**
 * Encodes the header that opens a unidirectional WebTransport stream for
 * `sessionId`: the {@link WEBTRANSPORT_STREAM_UNI} type varint then the Session
 * ID varint.
 */
export function encodeUniStreamHeader(sessionId: number | bigint): Uint8Array {
  return concatBytes(encodeQuicVarint(WEBTRANSPORT_STREAM_UNI), encodeQuicVarint(sessionId));
}

/**
 * The Quarter Stream ID of a WebTransport session: the CONNECT stream id divided
 * by four (draft-02 section 5), the context id prefixing every WT datagram.
 */
export function quarterStreamId(sessionId: number | bigint): bigint {
  const v = typeof sessionId === 'bigint' ? sessionId : BigInt(sessionId);
  return v >> 2n;
}

/**
 * Encodes a WebTransport datagram payload for `sessionId`: the Quarter Stream ID
 * varint then the datagram `payload`.
 */
export function encodeWtDatagram(sessionId: number | bigint, payload: Uint8Array): Uint8Array {
  return concatBytes(encodeQuicVarint(quarterStreamId(sessionId)), payload);
}

/**
 * Reads a WebTransport datagram: the leading Quarter Stream ID varint and the
 * remaining payload bytes, or `null` if the varint is truncated.
 */
export function decodeWtDatagram(
  input: Uint8Array,
): { quarterStreamId: bigint; payload: Uint8Array } | null {
  const dec = decodeQuicVarint(input);
  if (dec === null) {
    return null;
  }
  return { quarterStreamId: dec.value, payload: input.subarray(dec.length) };
}
