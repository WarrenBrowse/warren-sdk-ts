/**
 * EdgeConnect browser transport: opens a WebTransport-over-HTTP/3 session to a
 * Warren edge and tunnels the Warren multi-hop datapath inside it.
 *
 * This is the browser half of workstream D (the "edge == exit" zero-install
 * tier). The browser's own WebTransport implementation performs all the HTTP/3
 * and WebTransport framing (control/QPACK streams, the `0x41`+session-id stream
 * header, the datagram quarter-stream-id prefix); this class only writes and
 * reads the application bytes, which are {@link WarrenClientSession}-sealed
 * `WarrenMultihopFrame`s an exit HPKE-opens.
 *
 * Scope and honest limits: a Manifest V3 extension cannot capture the OS's IP
 * traffic, and `chrome.proxy` cannot target an in-page JS proxy, so this tier is
 * a datapath primitive for CODE-INITIATED traffic (an in-page tunneled client),
 * NOT a whole-browser VPN. It is deliberately a LOWER protection tier than the
 * native host datapath, for TWO independent reasons:
 *   1. SINGLE PARTY / SINGLE HOP. In the default {@link connectEdgeTunnelToExit}
 *      topology the browser's WebTransport terminates on the SAME node that
 *      holds the exit HPKE key, so ONE Warren party sees both the real source
 *      IP and the destination, like an ordinary single-hop VPN. This has none
 *      of the native path's multi-hop unlinkability, where no single node sees
 *      both ends.
 *   2. NESTED TLS. WebTransport is TLS-over-HTTP/3, so a Warren session nested
 *      inside it is the nested-TLS shape the native path avoids.
 * Label it as such in any UI: a lighter, single-hop, code-scoped tier; never
 * present it as equal to host-backed multi-hop.
 */

import {
  type ControlMessage,
  INDEPENDENT_SESSION_PLACEMENT,
  type SessionTokenLease,
  type VerifiedExit,
  WARREN_EDGE_PORT,
  WarrenClientSession,
  WarrenEdgeError,
  type WarrenMultihopFrame,
  decodeControlMessage,
  decodeMultihopFrame,
  encodeIpRequestV7,
  walkSessionTokens,
} from '@warrenbrowse/sdk-core';

/** The subset of the WHATWG streams + WebTransport surface this transport uses,
 * narrowed to a seam so it can be driven by a fake in Node tests. */
export interface EdgeWritable {
  getWriter(): {
    write(chunk: Uint8Array): Promise<void>;
    close(): Promise<void>;
    releaseLock(): void;
  };
}
export interface EdgeReadable {
  getReader(): {
    read(): Promise<{ value?: Uint8Array; done: boolean }>;
    releaseLock(): void;
  };
}
export interface EdgeBidiStream {
  readable: EdgeReadable;
  writable: EdgeWritable;
}
export interface WebTransportLike {
  readonly ready: Promise<void>;
  readonly closed: Promise<unknown>;
  createBidirectionalStream(): Promise<EdgeBidiStream>;
  readonly datagrams: { readable: EdgeReadable; writable: EdgeWritable };
  close(closeInfo?: { closeCode?: number; reason?: string }): void;
}

/** A SHA-256 certificate hash for pinning a self-signed edge cert (local/dev). */
export interface EdgeCertHash {
  algorithm: 'sha-256';
  value: Uint8Array;
}

export interface WarrenEdgeOptions {
  /** The edge WebTransport URL, e.g. `https://sg1.edge.example.com:8443/warren`
   * (the well-known {@link WARREN_EDGE_PORT}). */
  url: string;
  /** The exit's long-lived X25519 public key (32 bytes; `exitX25519PubkeyHex`
   * from a verified multi-hop directory). Frames are HPKE-sealed to it. */
  exitX25519Pubkey: Uint8Array;
  /** The exit's 16-byte routing tag. */
  exitId: Uint8Array;
  /** Pin the edge's certificate by SHA-256. This IS the production zero-config
   * path: `connectEdgeTunnelToExit` pins the directory-distributed ephemeral cert on
   * the well-known {@link WARREN_EDGE_PORT}. Only omit this when the edge
   * instead presents a WebPKI cover cert (a deployed cover domain), which needs
   * no pin. */
  serverCertificateHashes?: EdgeCertHash[];
  /** Factory seam. Defaults to the global `WebTransport`; injected in tests. */
  webTransportFactory?: (url: string, options: unknown) => WebTransportLike;
  /** Fixed HPKE ephemeral private key. TEST-ONLY, for deterministic vectors;
   * production omits it so a fresh CSPRNG ephemeral (forward secrecy) is used. */
  ephemeralPrivForTest?: Uint8Array;
  /** The hold on the session token this connection presents
   * (`TokenManager.claim`), released by {@link WarrenEdgeConnection.close}. */
  lease?: SessionTokenLease;
}

/**
 * Hardening guard for the {@link WarrenEdgeOptions.ephemeralPrivForTest} seam.
 *
 * The fixed HPKE ephemeral is a TEST-ONLY determinism aid: pinning it makes
 * every connection reuse the same exporter secret, and since `seq` restarts at
 * 0 on each reconnect under a fixed all-zero nonce, a fixed ephemeral on a real
 * transport would cause AEAD nonce reuse (plaintext recovery + forgery). We
 * therefore honor it ONLY when a WebTransport factory is also injected, which
 * only tests do. A production caller (real global `WebTransport`, no factory)
 * that passed `ephemeralPrivForTest` by mistake silently gets a fresh CSPRNG
 * ephemeral instead, so the footgun cannot fire on a real edge.
 */
export function selectSessionEphemeral(
  options: Pick<WarrenEdgeOptions, 'webTransportFactory' | 'ephemeralPrivForTest'>,
): Uint8Array | undefined {
  return options.webTransportFactory ? options.ephemeralPrivForTest : undefined;
}

function defaultFactory(url: string, options: unknown): WebTransportLike {
  const ctor = (globalThis as { WebTransport?: unknown }).WebTransport;
  if (typeof ctor !== 'function') {
    throw new WarrenEdgeError('handshake', 'WebTransport is not available in this environment');
  }
  return new (ctor as new (u: string, o: unknown) => WebTransportLike)(url, options);
}

/**
 * Reads exactly ONE self-delimiting {@link WarrenMultihopFrame} from a bidi
 * stream and returns it decoded, WITHOUT waiting for the peer to close the
 * stream. The exit's setup reply is a single sealed frame, but on ADMISSION it
 * keeps the setup stream open for the session, so a read-until-close would hang
 * (observed against the real fleet). The frame's LEB128-length-prefixed
 * ciphertext makes it self-delimiting, so we decode as soon as one complete
 * frame has arrived and stop reading.
 */
async function readOneFrame(readable: EdgeReadable): Promise<WarrenMultihopFrame> {
  const reader = readable.getReader();
  let buf = new Uint8Array(0);
  try {
    for (;;) {
      if (buf.length > 0) {
        try {
          return decodeMultihopFrame(buf);
        } catch (e) {
          // Only a still-incomplete frame is retryable (more bytes will finish
          // it); a structural error (bad version, trailing bytes) is fatal and
          // must not spin the read loop.
          if (!(e instanceof RangeError) || !/truncated/.test(e.message)) throw e;
        }
      }
      const { value, done } = await reader.read();
      if (value && value.length > 0) {
        const next = new Uint8Array(buf.length + value.length);
        next.set(buf, 0);
        next.set(value, buf.length);
        buf = next;
      }
      if (done) {
        // Stream ended: decode whatever arrived (throws if truly incomplete).
        return decodeMultihopFrame(buf);
      }
    }
  } finally {
    reader.releaseLock();
  }
}

/**
 * An open EdgeConnect session. Seals outbound frames and opens the exit's
 * reverse frames with a single {@link WarrenClientSession} (epoch 0; rekey is a
 * future increment). `seq` is monotonic per the nonce-uniqueness requirement.
 */
export class WarrenEdgeConnection {
  private seq = 0n;

  private constructor(
    private readonly wt: WebTransportLike,
    /** The HPKE sender session bound to the exit. */
    readonly session: WarrenClientSession,
    private readonly lease: SessionTokenLease | undefined,
  ) {}

  /** Opens the WebTransport session and sets up the HPKE sender against the
   * exit. Resolves once the transport is ready. */
  static async open(options: WarrenEdgeOptions): Promise<WarrenEdgeConnection> {
    const factory = options.webTransportFactory ?? defaultFactory;
    const wt = factory(options.url, {
      ...(options.serverCertificateHashes
        ? { serverCertificateHashes: options.serverCertificateHashes }
        : {}),
    });
    await wt.ready;
    const session = WarrenClientSession.create(
      options.exitX25519Pubkey,
      options.exitId,
      selectSessionEphemeral(options),
    );
    return new WarrenEdgeConnection(wt, session, options.lease);
  }

  /**
   * Perform the setup exchange: open a WebTransport bidi stream, write the one
   * sealed setup frame (`payload` is the multi-hop setup plaintext), finish the
   * send half, and return the exit's reply as an OPENED plaintext. The reply is
   * a reverse-direction `WarrenMultihopFrame` the exit sealed back.
   */
  async setup(payload: Uint8Array): Promise<Uint8Array> {
    const stream = await this.wt.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    try {
      await writer.write(this.session.sealFrameBytes(payload, 0, this.nextSeq()));
      await writer.close();
    } finally {
      writer.releaseLock();
    }
    return this.session.openResponse(await readOneFrame(stream.readable));
  }

  /**
   * Send the v7 IP-negotiation request the multi-hop exit expects (a control
   * `IpRequestV7` carrying the session tokens) and decode the exit's
   * `WarrenControlMessage` reply (an `IpAssign` with the tunnel IP on
   * admission). This is the correct request/reply pair for a real fleet exit;
   * `IpExhausted` / `Rejected` / `ExitDraining` are typed variants the caller
   * inspects.
   */
  async openTunnel(params: {
    tokens: Uint8Array[];
    wantsIpv6?: boolean;
    /** The session-placement hint (`prefer_ipv4`): `0.0.0.0` for an
     * independent session, the session's address for a bonded leg. */
    preferIpv4?: Uint8Array;
  }): Promise<ControlMessage> {
    const request = encodeIpRequestV7({
      tokens: params.tokens,
      ...(params.wantsIpv6 !== undefined ? { wantsIpv6: params.wantsIpv6 } : {}),
      ...(params.preferIpv4 !== undefined ? { preferIpv4: params.preferIpv4 } : {}),
    });
    const replyPlaintext = await this.setup(request);
    return decodeControlMessage(replyPlaintext);
  }

  /** Seal `payload` and send it as one WebTransport DATA datagram to the exit. */
  async sendData(payload: Uint8Array): Promise<void> {
    const writer = this.wt.datagrams.writable.getWriter();
    try {
      await writer.write(this.session.sealFrameBytes(payload, 0, this.nextSeq()));
    } finally {
      writer.releaseLock();
    }
  }

  /**
   * Async iterator over inbound DATA: each exit->client datagram is decoded and
   * HPKE-opened, yielding the recovered plaintext. Stops when the transport's
   * datagram stream ends (session closed).
   */
  async *incoming(): AsyncGenerator<Uint8Array> {
    const reader = this.wt.datagrams.readable.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (value) {
          const frame: WarrenMultihopFrame = decodeMultihopFrame(value);
          yield this.session.openResponse(frame);
        }
        if (done) {
          break;
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  /** Close the WebTransport session and release its session token. */
  close(): void {
    this.wt.close();
    this.lease?.release();
  }

  private nextSeq(): bigint {
    const s = this.seq;
    this.seq += 1n;
    return s;
  }
}

/** Everything a caller needs to reach a Warren exit via the EdgeConnect tier. */
export interface ConnectEdgeParams {
  /** The current epoch's pre-minted v7 session tokens (serialized
   * `SessionToken` bytes) in the order to try them, obtained AHEAD of this dial
   * from a `TokenManager` (`tokenManager.sessionStack(now)`). Minting is
   * deliberately NOT done here: issuing at connect time would correlate the
   * wallet-named issuance with this anonymous session (doc 64). An empty array
   * is refused. */
  tokens: Uint8Array[];
  /** Holds a token for this session before it is presented
   * (`tokenManager.claim`), so no other session of the process leads with it;
   * the admitted connection releases it on close. Without it, no token is
   * held. */
  claim?: (token: Uint8Array) => SessionTokenLease | undefined;
  /** The edge WebTransport URL, e.g. `https://sg1.edge.example.com:8443/warren`
   * (the well-known {@link WARREN_EDGE_PORT}). */
  url: string;
  /** The exit's long-lived X25519 public key (32 bytes). */
  exitX25519Pubkey: Uint8Array;
  /** The exit's 16-byte routing tag. */
  exitId: Uint8Array;
  /** Session features bitmask (see `@warrenbrowse/sdk-core` FEATURE_*). */
  features?: number;
  /** Pin the edge's ephemeral certificate by SHA-256, as `connectEdgeTunnelToExit`
   * derives from the signed directory. Only omit this when the edge presents a
   * WebPKI cover cert (a deployed cover domain), which needs no pin. */
  serverCertificateHashes?: EdgeCertHash[];
  /** Test seams. */
  webTransportFactory?: (url: string, options: unknown) => WebTransportLike;
  ephemeralPrivForTest?: Uint8Array;
}

/** Opens one WebTransport session for a token walk attempt. */
function openForAttempt(
  params: ConnectEdgeParams,
  lease: SessionTokenLease | undefined,
): Promise<WarrenEdgeConnection> {
  return WarrenEdgeConnection.open({
    url: params.url,
    exitX25519Pubkey: params.exitX25519Pubkey,
    exitId: params.exitId,
    ...(params.serverCertificateHashes
      ? { serverCertificateHashes: params.serverCertificateHashes }
      : {}),
    ...(params.webTransportFactory ? { webTransportFactory: params.webTransportFactory } : {}),
    ...(params.ephemeralPrivForTest ? { ephemeralPrivForTest: params.ephemeralPrivForTest } : {}),
    ...(lease ? { lease } : {}),
  });
}

/**
 * One-call EdgeConnect tier bring-up: walk the PRE-MINTED session tokens, one
 * WebTransport session and one {@link WarrenEdgeConnection.openTunnel} per
 * token, until the exit answers anything but `Rejected`. A real Warren exit
 * answers the setup stream with an `IpAssign` (the tunnel IP on admission) or a
 * typed `IpExhausted` / `ExitDraining`, returned for the caller to inspect.
 *
 * Every client of the wallet holds the same tokens, and the exit refuses a
 * serial another session holds anywhere in the fleet with the same `Rejected`
 * as an invalid token, spending nothing: so a refused setup is closed and the
 * next one leads with the next token (`walkSessionTokens`, at most
 * `MAX_SESSION_TOKENS` setups). Each setup declares an independent session
 * (`prefer_ipv4 = 0.0.0.0`), as the Rust SDK does.
 *
 * This is the browser-side entry point for the zero-install tier: a LOWER
 * protection tier than the native host datapath (nested TLS-over-HTTP/3),
 * carrying only code-initiated traffic; surface it labelled as such.
 *
 * @throws {WarrenEdgeError} `token_issuer` if `tokens` is empty;
 * `no_session_token` if no token could be claimed or the exit refused every
 * one; `handshake` if the environment has no WebTransport.
 */
export async function connectEdgeTunnel(
  params: ConnectEdgeParams,
): Promise<{ connection: WarrenEdgeConnection; control: ControlMessage }> {
  if (params.tokens.length === 0) {
    throw new WarrenEdgeError('token_issuer', 'no pre-minted session tokens for this epoch');
  }
  const walked = await walkSessionTokens(
    params.tokens,
    async (token, lease) => {
      const connection = await openForAttempt(params, lease);
      try {
        const control = await connection.openTunnel({
          tokens: [token],
          preferIpv4: INDEPENDENT_SESSION_PLACEMENT,
        });
        return { connection, control, close: () => connection.close() };
      } catch (error) {
        connection.close();
        throw error;
      }
    },
    params.claim,
  );
  return { connection: walked.attempt.connection, control: walked.attempt.control };
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('odd-length hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error('invalid hex');
    out[i] = byte;
  }
  return out;
}

/** Splits a `host:port` (or `[v6]:port`) authority into its host, dropping the port. */
function hostOf(endpoint: string): string {
  if (endpoint.startsWith('[')) {
    const end = endpoint.indexOf(']');
    if (end !== -1) return endpoint.slice(0, end + 1);
  }
  const i = endpoint.lastIndexOf(':');
  return i === -1 ? endpoint : endpoint.slice(0, i);
}

/**
 * Bring up an EdgeConnect session to a verified directory exit that advertises an
 * edge, with zero manual configuration: the WebTransport URL is derived from the
 * node host plus the well-known {@link WARREN_EDGE_PORT}, and the self-signed
 * edge cert is pinned from the directory's `edgeCertSha256` (auto-discovered, no
 * SHA to publish by hand). The pin rides the server-signed directory envelope, so
 * a compromised serve host cannot silently substitute it. Returns the exit's
 * {@link ControlMessage} reply ({@link connectEdgeTunnel}): a real fleet exit
 * answers the setup stream with a control-framed `IpAssign` (the tunnel IP).
 *
 * This is the one-call entry point the browser extension uses for the
 * zero-install tier over a verified directory.
 *
 * @throws {WarrenEdgeError} `no_edge_pin` if the exit advertises no edge cert
 * (`edgeCertSha256` absent): refuses rather than dial an unpinned URL.
 */
export async function connectEdgeTunnelToExit(
  exit: VerifiedExit,
  params: {
    tokens: Uint8Array[];
    claim?: (token: Uint8Array) => SessionTokenLease | undefined;
    features?: number;
    webTransportFactory?: (url: string, options: unknown) => WebTransportLike;
    ephemeralPrivForTest?: Uint8Array;
  },
): Promise<{ connection: WarrenEdgeConnection; control: ControlMessage }> {
  if (exit.edgeCertSha256 === undefined) {
    throw new WarrenEdgeError(
      'no_edge_pin',
      'exit advertises no edge cert (edgeCertSha256 absent)',
    );
  }
  return connectEdgeTunnel({
    tokens: params.tokens,
    ...(params.claim ? { claim: params.claim } : {}),
    url: `https://${hostOf(exit.endpoint)}:${WARREN_EDGE_PORT}/warren`,
    exitX25519Pubkey: hexToBytes(exit.exitX25519PubkeyHex),
    exitId: hexToBytes(exit.exitIdHex),
    serverCertificateHashes: [{ algorithm: 'sha-256', value: hexToBytes(exit.edgeCertSha256) }],
    ...(params.features !== undefined ? { features: params.features } : {}),
    ...(params.webTransportFactory ? { webTransportFactory: params.webTransportFactory } : {}),
    ...(params.ephemeralPrivForTest ? { ephemeralPrivForTest: params.ephemeralPrivForTest } : {}),
  });
}
