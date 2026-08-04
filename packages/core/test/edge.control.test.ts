import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  CONTROL_VERSION_V3,
  decodeControlMessage,
  encodeIpRequestV7,
} from '../src/edge/control.js';
import { encodeLeb128 } from '../src/edge/varint.js';

const hexToBytes = (h: string): Uint8Array =>
  new Uint8Array((h.match(/../g) ?? []).map((x) => Number.parseInt(x, 16)));

/**
 * `vectors/control.json` is the shared cross-implementation contract for the
 * `/v3` control messages (warrenguard-multihop `control.rs`, framed
 * `0xC0 0x03 || postcard(enum)`). Every vector byte is authoritative: a
 * mismatch is a real wire regression against live exits, never a test nuisance.
 */
const vectorsPath = fileURLToPath(new URL('../../../vectors/control.json', import.meta.url));

interface ControlVector {
  name: string;
  bytes_hex: string;
  ipv4?: number[];
  prefix_len?: number;
  gateway_ipv4?: number[];
  daita_spec?: {
    machine_specs: string[];
    max_padding_frac: number;
    max_blocking_frac: number;
  } | null;
  deadline_unix_secs?: number;
  reason_code?: number;
}

const vectorFile = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
  first_byte: number;
  version: number;
  vectors: ControlVector[];
};

const byName = (name: string): ControlVector => {
  const v = vectorFile.vectors.find((x) => x.name === name);
  if (!v) throw new Error(`missing golden vector ${name}`);
  return v;
};

describe('vectors/control.json (shared /v3 golden vectors)', () => {
  it('pins the version byte the SDK speaks', () => {
    expect(vectorFile.version).toBe(CONTROL_VERSION_V3);
    expect(CONTROL_VERSION_V3).toBe(0x03);
    for (const v of vectorFile.vectors) {
      const bytes = hexToBytes(v.bytes_hex);
      expect(bytes[0]).toBe(vectorFile.first_byte);
      expect(bytes[1]).toBe(CONTROL_VERSION_V3);
    }
  });

  it('decodes the ip_assign vector byte-exactly (daita not granted)', () => {
    const v = byName('ip_assign');
    const msg = decodeControlMessage(hexToBytes(v.bytes_hex));
    if (msg.type !== 'ipAssign') throw new Error('expected ipAssign');
    expect(Array.from(msg.ipv4)).toEqual(v.ipv4);
    expect(msg.prefixLen).toBe(v.prefix_len);
    expect(Array.from(msg.gatewayIpv4)).toEqual(v.gateway_ipv4);
    expect(msg.ipv6).toBeNull();
    expect(msg.gatewayIpv6).toBeNull();
    // The honest "DAITA is not running" signal: the caller must surface it.
    expect(msg.daitaSpec).toBeNull();
  });

  it('decodes the ip_assign_with_daita vector byte-exactly (defense granted)', () => {
    const v = byName('ip_assign_with_daita');
    const msg = decodeControlMessage(hexToBytes(v.bytes_hex));
    if (msg.type !== 'ipAssign') throw new Error('expected ipAssign');
    expect(Array.from(msg.ipv4)).toEqual(v.ipv4);
    expect(msg.prefixLen).toBe(v.prefix_len);
    expect(Array.from(msg.gatewayIpv4)).toEqual(v.gateway_ipv4);
    const spec = v.daita_spec;
    if (!spec) throw new Error('vector must carry a granted daita_spec');
    expect(msg.daitaSpec).not.toBeNull();
    expect(msg.daitaSpec?.machineSpecs).toEqual(spec.machine_specs);
    expect(msg.daitaSpec?.maxPaddingFrac).toBe(spec.max_padding_frac);
    expect(msg.daitaSpec?.maxBlockingFrac).toBe(spec.max_blocking_frac);
  });

  it('decodes ip_exhausted and rejected', () => {
    expect(decodeControlMessage(hexToBytes(byName('ip_exhausted').bytes_hex)).type).toBe(
      'ipExhausted',
    );
    expect(decodeControlMessage(hexToBytes(byName('rejected').bytes_hex)).type).toBe('rejected');
  });

  it('decodes exit_draining with its deadline + reason', () => {
    const v = byName('exit_draining');
    const msg = decodeControlMessage(hexToBytes(v.bytes_hex));
    if (msg.type !== 'exitDraining') throw new Error('expected exitDraining');
    expect(msg.deadlineUnixSecs).toBe(BigInt(v.deadline_unix_secs ?? 0));
    expect(msg.reasonCode).toBe(v.reason_code);
  });

  it('rejects the client -> exit ip_request vectors arriving at the client', () => {
    for (const name of ['ip_request_minimal', 'ip_request_full']) {
      expect(() => decodeControlMessage(hexToBytes(byName(name).bytes_hex))).toThrow(
        /unexpected control variant/,
      );
    }
  });
});

/**
 * The client -> exit `IpRequestV7`: pinned byte-for-byte to the Rust
 * `ip_request_v7_wire_layout_is_frozen` golden layout (warrenguard-multihop
 * `control.rs`), /v3: the trailing byte is `wants_daita`. A mismatch means a
 * real exit's `try_decode_control` rejects the client.
 */
describe('encodeIpRequestV7 (WarrenControlMessage, client -> exit)', () => {
  it('matches the frozen Rust golden layout (wants_daita off)', () => {
    const token = new Uint8Array(354).fill(0xcd);
    const bytes = encodeIpRequestV7({ tokens: [token], wantsIpv6: false });
    const expected = new Uint8Array([
      0xc0, // CONTROL_FIRST_BYTE
      0x03, // CONTROL_VERSION_V3
      0x05, // enum discriminant: IpRequestV7
      0x00, // prefer_ipv4: Option None
      0x00, // wants_ipv6: false
      0x01, // session_tokens: Vec length = 1
      ...token,
      0x00, // wants_daita: false
    ]);
    expect(Array.from(bytes)).toEqual(Array.from(expected));
  });

  it('sets the wants_daita trailing byte when the defense is requested', () => {
    const token = new Uint8Array(354).fill(0xcd);
    const bytes = encodeIpRequestV7({ tokens: [token], wantsDaita: true });
    expect(bytes[bytes.length - 1]).toBe(0x01);
    // Everything before the capability byte is unchanged by the request.
    const off = encodeIpRequestV7({ tokens: [token] });
    expect(Array.from(bytes.subarray(0, bytes.length - 1))).toEqual(
      Array.from(off.subarray(0, off.length - 1)),
    );
  });

  it('sets the wants_ipv6 byte and a Some prefer_ipv4', () => {
    const token = new Uint8Array(354).fill(0x11);
    const bytes = encodeIpRequestV7({
      tokens: [token],
      wantsIpv6: true,
      preferIpv4: new Uint8Array([10, 0, 0, 9]),
    });
    // 0xC0 0x03 0x05 | prefer Some(0x01)+4B | wants_ipv6 0x01 | count 0x01 | token
    expect(Array.from(bytes.subarray(0, 11))).toEqual([
      0xc0, 0x03, 0x05, 0x01, 10, 0, 0, 9, 0x01, 0x01, 0x11,
    ]);
  });

  it('rejects an empty token stack and a wrong-length token', () => {
    expect(() => encodeIpRequestV7({ tokens: [] })).toThrow(/at least one/);
    expect(() => encodeIpRequestV7({ tokens: [new Uint8Array(10)] })).toThrow(/354 bytes/);
  });
});

describe('decodeControlMessage (WarrenControlMessage, exit -> client)', () => {
  it('decodes a dual-stack IpAssign (ipv6 present, daita absent)', () => {
    const v6 = new Uint8Array(16).fill(0xaa);
    const gw6 = new Uint8Array(16).fill(0xbb);
    const bytes = new Uint8Array([
      0xc0,
      0x03,
      0x01, // variant IpAssign
      10,
      66,
      0,
      5, // ipv4
      24, // prefix_len
      10,
      66,
      0,
      1, // gateway_ipv4
      0x01, // ipv6 Some
      ...v6,
      64, // prefix_len_v6
      0x01, // gateway_ipv6 Some
      ...gw6,
      0x00, // daita_spec None
    ]);
    const msg = decodeControlMessage(bytes);
    if (msg.type !== 'ipAssign') throw new Error('expected ipAssign');
    expect(msg.ipv6).not.toBeNull();
    expect(Array.from(msg.ipv6 as Uint8Array)).toEqual(Array.from(v6));
    expect(msg.prefixLenV6).toBe(64);
    expect(Array.from(msg.gatewayIpv6 as Uint8Array)).toEqual(Array.from(gw6));
    expect(msg.daitaSpec).toBeNull();
  });

  it('decodes ExitDraining with its deadline + reason', () => {
    const deadline = 1_800_000_000n;
    const bytes = new Uint8Array([0xc0, 0x03, 0x04, ...encodeLeb128(deadline), 7]);
    const msg = decodeControlMessage(bytes);
    if (msg.type !== 'exitDraining') throw new Error('expected exitDraining');
    expect(msg.deadlineUnixSecs).toBe(deadline);
    expect(msg.reasonCode).toBe(7);
  });

  it('rejects a non-control first byte (a 0x07 where the 0xC0 marker is required)', () => {
    expect(() => decodeControlMessage(hexToBytes('070a420003'))).toThrow(/not a control message/);
  });

  it('rejects the retired 0x01 and 0x02 control versions loudly', () => {
    // A 0x01/0x02 peer cannot express whether the traffic-analysis defense is
    // running; decoding either would reintroduce the silent-undefended bug
    // /v3 exists to prevent.
    expect(() => decodeControlMessage(hexToBytes('c00101'))).toThrow(
      /unsupported control version 1/,
    );
    expect(() => decodeControlMessage(hexToBytes('c00201'))).toThrow(
      /unsupported control version 2/,
    );
  });

  it('rejects a client -> exit variant (IpRequest = 0) arriving at the client', () => {
    expect(() => decodeControlMessage(hexToBytes('c00300'))).toThrow(/unexpected control variant/);
  });

  it('rejects trailing bytes after a complete message', () => {
    expect(() => decodeControlMessage(hexToBytes('c003010a420007180a42000100000000ff'))).toThrow(
      /trailing bytes/,
    );
  });

  it('rejects a truncated daita_spec and an invalid Option tag', () => {
    // ipv6 Option tag = 2 (neither 0 nor 1).
    expect(() => decodeControlMessage(hexToBytes('c003010a420007180a42000102'))).toThrow(
      /invalid Option tag/,
    );
    // daita_spec Some, then nothing: machine_specs count is missing.
    expect(() => decodeControlMessage(hexToBytes('c003010a420007180a42000100000001'))).toThrow(
      /truncated/,
    );
  });
});
