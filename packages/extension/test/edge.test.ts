import { decodeMultihopFrame } from '@warrenbrowse/sdk-core';
import { describe, expect, it } from 'vitest';

const hexToBytes = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, 'hex'));
import {
  type EdgeBidiStream,
  type EdgeReadable,
  type EdgeWritable,
  WarrenEdgeConnection,
  type WebTransportLike,
  selectSessionEphemeral,
} from '../src/edge.js';

const EXIT_PUB = hexToBytes('1a239249ea74403babc01f32df9931a16f71ac8972c461d69fed15640e310639');
const EXIT_ID = new Uint8Array(16).fill(0xa1);
const EPHEMERAL = new Uint8Array(32).fill(0x22);
// A reverse frame sealed by a real Rust exit for this exact session (epoch 7,
// seq 99, plaintext "exit-reply-to-browser"), reused as the fake edge's reply.
const REVERSE_FRAME = hexToBytes(
  '01a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a107630faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f200093fbafe93b32ac6be23dfeb0be4fb8159436a90f4b0b6bfbfa18844c42c9b4646c3c34719d',
);

function readableOf(chunks: Uint8Array[]): EdgeReadable {
  let i = 0;
  return {
    getReader() {
      return {
        async read() {
          if (i < chunks.length) {
            return { value: chunks[i++], done: false };
          }
          return { value: undefined, done: true };
        },
        releaseLock() {},
      };
    },
  };
}

function capturingWritable(sink: Uint8Array[]): EdgeWritable {
  return {
    getWriter() {
      return {
        async write(chunk: Uint8Array) {
          sink.push(chunk);
        },
        async close() {},
        releaseLock() {},
      };
    },
  };
}

interface FakeCapture {
  setupWrites: Uint8Array[];
  datagramWrites: Uint8Array[];
}

function fakeWebTransport(capture: FakeCapture): WebTransportLike {
  return {
    ready: Promise.resolve(),
    closed: new Promise(() => {}),
    async createBidirectionalStream(): Promise<EdgeBidiStream> {
      return {
        writable: capturingWritable(capture.setupWrites),
        readable: readableOf([REVERSE_FRAME]), // the exit's setup reply
      };
    },
    datagrams: {
      writable: capturingWritable(capture.datagramWrites),
      readable: readableOf([REVERSE_FRAME]), // one inbound DATA datagram
    },
    close() {},
  };
}

async function openConn(capture: FakeCapture): Promise<WarrenEdgeConnection> {
  return WarrenEdgeConnection.open({
    url: 'https://edge.test:51443/warren',
    exitX25519Pubkey: EXIT_PUB,
    exitId: EXIT_ID,
    ephemeralPrivForTest: EPHEMERAL,
    webTransportFactory: () => fakeWebTransport(capture),
  });
}

describe('selectSessionEphemeral (hardening: fixed test ephemeral needs an injected factory)', () => {
  it('honors the fixed ephemeral when a WebTransport factory is injected (test path)', () => {
    const eph = new Uint8Array(32).fill(0x22);
    const factory = () => fakeWebTransport({ setupWrites: [], datagramWrites: [] });
    expect(
      selectSessionEphemeral({ webTransportFactory: factory, ephemeralPrivForTest: eph }),
    ).toBe(eph);
  });

  it('ignores a stray fixed ephemeral in production (no factory) so it cannot pin the nonce', () => {
    const eph = new Uint8Array(32).fill(0x22);
    // No factory = real global WebTransport = production: the seam must be dropped.
    expect(selectSessionEphemeral({ ephemeralPrivForTest: eph })).toBeUndefined();
  });
});

// A stream that delivers ONE frame then never closes (never yields done), like a
// real exit that keeps the setup stream open after admitting the session. A
// read-until-close would hang here; a single-frame read must not.
function readableFrameThenHang(frame: Uint8Array): EdgeReadable {
  let sent = false;
  return {
    getReader() {
      return {
        async read() {
          if (!sent) {
            sent = true;
            return { value: frame, done: false };
          }
          return new Promise<{ value?: Uint8Array; done: boolean }>(() => {}); // never resolves
        },
        releaseLock() {},
      };
    },
  };
}

describe('WarrenEdgeConnection', () => {
  it('setup() returns after one frame without waiting for the exit to close the stream', async () => {
    // Regression: on admission the exit sends its reply frame then keeps the
    // setup stream open; setup() must decode the single frame and return, not
    // hang waiting for a close that never comes.
    const conn = await WarrenEdgeConnection.open({
      url: 'https://edge.test:51443/warren',
      exitX25519Pubkey: EXIT_PUB,
      exitId: EXIT_ID,
      ephemeralPrivForTest: EPHEMERAL,
      webTransportFactory: () => ({
        ready: Promise.resolve(),
        closed: new Promise(() => {}),
        async createBidirectionalStream(): Promise<EdgeBidiStream> {
          return {
            writable: capturingWritable([]),
            readable: readableFrameThenHang(REVERSE_FRAME),
          };
        },
        datagrams: { writable: capturingWritable([]), readable: readableOf([]) },
        close() {},
      }),
    });

    const reply = await conn.setup(new TextEncoder().encode('browser-setup'));
    expect(new TextDecoder().decode(reply)).toBe('exit-reply-to-browser');
  });

  it('seals the setup frame and opens the exit reply', async () => {
    const capture: FakeCapture = { setupWrites: [], datagramWrites: [] };
    const conn = await openConn(capture);

    const reply = await conn.setup(new TextEncoder().encode('browser-setup'));

    // Exactly one sealed setup frame was written to the bidi stream.
    expect(capture.setupWrites).toHaveLength(1);
    const sent = decodeMultihopFrame(capture.setupWrites[0]!);
    expect(sent.version).toBe(1);
    expect(Array.from(sent.exitId)).toEqual(Array.from(EXIT_ID));
    expect(sent.epoch).toBe(0);
    expect(sent.seq).toBe(0n);
    expect(sent.ciphertext.length).toBe('browser-setup'.length);

    // The reply frame was HPKE-opened to the exit's plaintext.
    expect(new TextDecoder().decode(reply)).toBe('exit-reply-to-browser');
  });

  it('seals DATA datagrams with a monotonic seq', async () => {
    const capture: FakeCapture = { setupWrites: [], datagramWrites: [] };
    const conn = await openConn(capture);

    await conn.sendData(new TextEncoder().encode('packet-one'));
    await conn.sendData(new TextEncoder().encode('packet-two'));

    expect(capture.datagramWrites).toHaveLength(2);
    expect(decodeMultihopFrame(capture.datagramWrites[0]!).seq).toBe(0n);
    expect(decodeMultihopFrame(capture.datagramWrites[1]!).seq).toBe(1n);
  });

  it('opens inbound DATA datagrams via the reverse HPKE path', async () => {
    const capture: FakeCapture = { setupWrites: [], datagramWrites: [] };
    const conn = await openConn(capture);

    const first = await conn.incoming().next();
    expect(first.done).toBe(false);
    expect(new TextDecoder().decode(first.value)).toBe('exit-reply-to-browser');
  });

  // Locks the wiring: openTunnel seals an IpRequestV7 control message (what the
  // real exit expects) and routes the opened reply through the control-message
  // decoder. The REVERSE_FRAME opens to a non-control plaintext, so the decoder
  // rejects it. The IpRequestV7 layout + IpAssign decode are pinned in
  // `sdk-core` `edge.control.test.ts`.
  it('openTunnel sends an IpRequestV7 and decodes the reply as a control message', async () => {
    const capture: FakeCapture = { setupWrites: [], datagramWrites: [] };
    const conn = await openConn(capture);
    const token = new Uint8Array(354).fill(0xcd);

    await expect(conn.openTunnel({ tokens: [token] })).rejects.toThrow(/not a control message/);

    // The IpRequestV7 (0xC0 0x03 0x05 | prefer None | wants_ipv6 | count |
    // token | wants_daita) was sealed and sent before the reply was decoded.
    expect(capture.setupWrites).toHaveLength(1);
    const sent = decodeMultihopFrame(capture.setupWrites[0]!);
    expect(Array.from(sent.exitId)).toEqual(Array.from(EXIT_ID));
    expect(sent.ciphertext.length).toBe(6 + 354 + 1); // header + 354-byte token + wants_daita
  });
});
