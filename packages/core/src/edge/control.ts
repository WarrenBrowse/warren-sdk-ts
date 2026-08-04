/**
 * `WarrenControlMessage` decode: the exit's reply on the multi-hop setup stream
 * (an {@link IpAssign} with the tunnel IP for a nominal setup).
 *
 * Wire (warrenguard-multihop `control.rs`): sealed plaintext framed
 * `0xC0 | 0x03 | postcard(WarrenControlMessage)`, the 0xC0 disambiguating it
 * from an IP packet on the same channel. The postcard enum discriminant is a
 * LEB128 varint; the exit -> client variants are `IpAssign` (1), `IpExhausted`
 * (2), `Rejected` (3), `ExitDraining` (4). `IpRequest` (0) / `IpRequestV7` (5)
 * are client -> exit and never arrive here.
 */

import { decodeLeb128, encodeLeb128 } from './varint.js';

/** Reserved first byte marking a control message on the sealed channel. */
export const CONTROL_FIRST_BYTE = 0xc0;
/**
 * Control protocol version byte for the current layout (`/v3`: the DAITA
 * capability echo, `wants_daita` on the requests and `daita_spec` on
 * `IpAssign`). The retired `0x01`/`0x02` bytes are never decoded: a peer
 * speaking them cannot express whether the traffic-analysis defense is
 * running, and a silently-undefended session is exactly the failure this
 * version exists to make impossible.
 */
export const CONTROL_VERSION_V3 = 0x03;

/** postcard enum discriminant of the client -> exit `IpRequestV7` variant. */
const IP_REQUEST_V7_VARIANT = 5;
/** One serialized Privacy Pass session token (raw bytes, no length prefix). */
const SESSION_TOKEN_LEN = 354;
/** Upper bound on the token stack a request may present. */
const MAX_SESSION_TOKENS = 8;

/**
 * Encodes the client -> exit `WarrenControlMessage::IpRequestV7`: the v7
 * anonymous-admission request a multi-hop exit expects as the FIRST setup-stream
 * frame. This is the request an EdgeConnect client seals and sends to negotiate
 * its tunnel IP.
 *
 * Byte layout, frozen to match the Rust `ip_request_v7_wire_layout_is_frozen`
 * golden vector (`warrenguard-multihop` control.rs):
 *   `0xC0 0x03 0x05 <prefer_ipv4 Option> <wants_ipv6 bool> <count LEB128>
 *   tokens… <wants_daita bool>`
 * where `prefer_ipv4` is `0x00` (None) or `0x01`+4 bytes, and each token is
 * {@link SESSION_TOKEN_LEN} raw bytes. `wantsDaita` asks the exit for the
 * traffic-analysis defense; the exit answers via {@link IpAssign.daitaSpec}
 * (same capability-echo contract as `wants_ipv6`).
 *
 * @throws RangeError if `tokens` is empty or over {@link MAX_SESSION_TOKENS}, a
 * token is the wrong length, or `preferIpv4` is not 4 bytes.
 */
export function encodeIpRequestV7(params: {
  tokens: Uint8Array[];
  wantsIpv6?: boolean;
  preferIpv4?: Uint8Array | null;
  wantsDaita?: boolean;
}): Uint8Array {
  if (params.tokens.length === 0) {
    throw new RangeError('IpRequestV7 must carry at least one session token');
  }
  if (params.tokens.length > MAX_SESSION_TOKENS) {
    throw new RangeError(`at most ${MAX_SESSION_TOKENS} session tokens`);
  }
  for (const t of params.tokens) {
    if (t.length !== SESSION_TOKEN_LEN) {
      throw new RangeError(`session token must be ${SESSION_TOKEN_LEN} bytes, got ${t.length}`);
    }
  }
  const preferIpv4 = params.preferIpv4 ?? null;
  if (preferIpv4 !== null && preferIpv4.length !== 4) {
    throw new RangeError('preferIpv4 must be 4 bytes');
  }

  const variant = encodeLeb128(IP_REQUEST_V7_VARIANT);
  const count = encodeLeb128(params.tokens.length);
  const total =
    2 + // 0xC0 0x03
    variant.length +
    (preferIpv4 === null ? 1 : 1 + 4) +
    1 + // wants_ipv6
    count.length +
    params.tokens.length * SESSION_TOKEN_LEN +
    1; // wants_daita

  const out = new Uint8Array(total);
  let o = 0;
  out[o++] = CONTROL_FIRST_BYTE;
  out[o++] = CONTROL_VERSION_V3;
  out.set(variant, o);
  o += variant.length;
  if (preferIpv4 === null) {
    out[o++] = 0x00; // Option::None
  } else {
    out[o++] = 0x01; // Option::Some
    out.set(preferIpv4, o);
    o += 4;
  }
  out[o++] = params.wantsIpv6 ? 0x01 : 0x00;
  out.set(count, o);
  o += count.length;
  for (const t of params.tokens) {
    out.set(t, o);
    o += SESSION_TOKEN_LEN;
  }
  out[o++] = params.wantsDaita ? 0x01 : 0x00;
  return out;
}

/**
 * The maybenot machine set the exit committed to drive on its downlink; the
 * client must drive the same spec on its uplink. Mirrors the Rust
 * `warrenguard_wire::DaitaConfig` postcard layout.
 */
export interface DaitaConfig {
  /** Serialized maybenot machines (`Machine::serialize` strings). */
  machineSpecs: string[];
  /** Hard cap on the fraction of total packets that may be padding, 0..=1. */
  maxPaddingFrac: number;
  /** Hard cap on the fraction of total time that may be blocked, 0..=1. */
  maxBlockingFrac: number;
}

/** The exit's authoritative tunnel-IP allocation. */
export interface IpAssign {
  type: 'ipAssign';
  /** Allocated host IPv4 (4 bytes). */
  ipv4: Uint8Array;
  /** IPv4 subnet prefix length (e.g. 16 for a `/16`). */
  prefixLen: number;
  /** IPv4 subnet gateway / exit-side TUN address (4 bytes). */
  gatewayIpv4: Uint8Array;
  /** Allocated host IPv6 (16 bytes), or null when the exit granted no v6. */
  ipv6: Uint8Array | null;
  /** IPv6 subnet prefix length; ignored when `ipv6` is null. */
  prefixLenV6: number;
  /** IPv6 subnet gateway (16 bytes), or null when no v6. */
  gatewayIpv6: Uint8Array | null;
  /**
   * The traffic-analysis defense the exit granted for this session, or null
   * when it did not. Null in reply to a `wants_daita` request means the
   * defense is NOT running: the caller must surface that, never report the
   * session as defended while padding nothing.
   */
  daitaSpec: DaitaConfig | null;
}

/** The exit's IPv4 pool is exhausted; the client should terminate. */
export interface IpExhausted {
  type: 'ipExhausted';
}

/** The setup was refused by policy (not admitted). */
export interface Rejected {
  type: 'rejected';
}

/** Mid-session drain advisory: migrate off this exit before the deadline. */
export interface ExitDraining {
  type: 'exitDraining';
  /** Absolute Unix epoch seconds after which the exit hard-closes. */
  deadlineUnixSecs: bigint;
  /** Opaque reason (0 = maintenance). */
  reasonCode: number;
}

/** An exit -> client {@link WarrenControlMessage} the client may observe. */
export type ControlMessage = IpAssign | IpExhausted | Rejected | ExitDraining;

/**
 * Decodes an exit -> client `WarrenControlMessage` from an opened setup-stream
 * plaintext.
 *
 * @throws RangeError on a missing/incorrect `0xC0 0x03` frame (retired
 * versions 0x01/0x02 included), an unknown or client -> exit variant,
 * truncation, or trailing bytes (one plaintext is exactly one control
 * message, matching the Rust `try_decode_control` rule).
 */
export function decodeControlMessage(plaintext: Uint8Array): ControlMessage {
  if (plaintext.length < 2) {
    throw new RangeError(`truncated control message: ${plaintext.length} bytes`);
  }
  if (plaintext[0] !== CONTROL_FIRST_BYTE) {
    throw new RangeError(
      `not a control message: first byte ${plaintext[0]} != 0x${CONTROL_FIRST_BYTE.toString(16)}`,
    );
  }
  if (plaintext[1] !== CONTROL_VERSION_V3) {
    throw new RangeError(
      `unsupported control version ${plaintext[1]}, expected ${CONTROL_VERSION_V3}`,
    );
  }

  const body = plaintext.subarray(2);
  let o = 0;
  const need = (n: number, what: string): void => {
    if (o + n > body.length) {
      throw new RangeError(`truncated control message: need ${n} more bytes for ${what}`);
    }
  };
  const readU8 = (what: string): number => {
    need(1, what);
    const b = body[o] ?? 0;
    o += 1;
    return b;
  };
  const readBytes = (n: number, what: string): Uint8Array => {
    need(n, what);
    const s = body.slice(o, o + n);
    o += n;
    return s;
  };
  // postcard Option: a single 0/1 discriminant, then the payload iff 1.
  const readOptionBytes = (n: number, what: string): Uint8Array | null => {
    const tag = readU8(`${what} tag`);
    if (tag === 0) {
      return null;
    }
    if (tag !== 1) {
      throw new RangeError(`invalid Option tag ${tag} for ${what}`);
    }
    return readBytes(n, what);
  };
  // postcard String: LEB128 byte length, then UTF-8 bytes.
  const readString = (what: string): string => {
    const lenDec = decodeLeb128(body.subarray(o));
    o += lenDec.length;
    return new TextDecoder().decode(readBytes(Number(lenDec.value), what));
  };
  // postcard f64: 8 bytes, IEEE 754 little-endian.
  const readF64 = (what: string): number => {
    const b = readBytes(8, what);
    return new DataView(b.buffer, b.byteOffset, 8).getFloat64(0, true);
  };
  const readOptionDaitaConfig = (): DaitaConfig | null => {
    const tag = readU8('daita_spec tag');
    if (tag === 0) {
      return null;
    }
    if (tag !== 1) {
      throw new RangeError(`invalid Option tag ${tag} for daita_spec`);
    }
    const countDec = decodeLeb128(body.subarray(o));
    o += countDec.length;
    const machineSpecs: string[] = [];
    for (let i = 0n; i < countDec.value; i++) {
      machineSpecs.push(readString('machine_spec'));
    }
    const maxPaddingFrac = readF64('max_padding_frac');
    const maxBlockingFrac = readF64('max_blocking_frac');
    return { machineSpecs, maxPaddingFrac, maxBlockingFrac };
  };

  const variantDec = decodeLeb128(body.subarray(o));
  o += variantDec.length;
  const variant = variantDec.value;

  let msg: ControlMessage;
  switch (variant) {
    case 1n: {
      const ipv4 = readBytes(4, 'ipv4');
      const prefixLen = readU8('prefix_len');
      const gatewayIpv4 = readBytes(4, 'gateway_ipv4');
      const ipv6 = readOptionBytes(16, 'ipv6');
      const prefixLenV6 = readU8('prefix_len_v6');
      const gatewayIpv6 = readOptionBytes(16, 'gateway_ipv6');
      const daitaSpec = readOptionDaitaConfig();
      msg = {
        type: 'ipAssign',
        ipv4,
        prefixLen,
        gatewayIpv4,
        ipv6,
        prefixLenV6,
        gatewayIpv6,
        daitaSpec,
      };
      break;
    }
    case 2n:
      msg = { type: 'ipExhausted' };
      break;
    case 3n:
      msg = { type: 'rejected' };
      break;
    case 4n: {
      const dec = decodeLeb128(body.subarray(o));
      o += dec.length;
      const reasonCode = readU8('reason_code');
      msg = { type: 'exitDraining', deadlineUnixSecs: dec.value, reasonCode };
      break;
    }
    default:
      throw new RangeError(`unexpected control variant ${variant} (not an exit->client message)`);
  }

  if (o !== body.length) {
    throw new RangeError(`trailing bytes after control message: ${body.length - o} left`);
  }
  return msg;
}

/** Formats an {@link IpAssign} IPv4 as dotted-quad (for logging/UX). */
export function ipv4ToString(ipv4: Uint8Array): string {
  return Array.from(ipv4).join('.');
}
