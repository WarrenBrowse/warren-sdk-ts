/**
 * Native binding surface of the Warren proxy datapath (napi-rs).
 *
 * Every rejected promise carries a `message` of the form `"<kind>: text"`
 * where `kind` is one of `identity | api | discovery | tunnel | config |
 * unsupported` (mirrors the sibling SDKs' sealed `WarrenError` hierarchy).
 * Split on the first `": "` to get a stable, JS-dispatchable code plus a
 * redacted, human-readable message (never a pubkey/address/IP/secret).
 */

/** Optional client knobs beyond the required constructor arguments. */
export interface WarrenProxyOptions {
  /** Anti-censorship fallback hostnames tried when the primary `apiBase` is unreachable. */
  alternativeHosts?: string[];
  /** Offline multihop-directory ROOT Ed25519 pubkey pin (64-hex). */
  multihopRootPinHex?: string;
  /** Enables the DAITA uplink traffic-analysis defense on multihop tunnels. */
  daita?: boolean;
  /** Pins DAITA to a named curated-pool machine; implies `daita`. */
  daitaMachine?: string;
  /** Requests a dual-stack IPv6 allocation from exits that grant one. */
  requestIpv6?: boolean;
  /**
   * Directory to persist the anti-rollback floors and the TOFU server pin
   * across restarts. Without it they live in memory only (reset per launch).
   */
  stateDir?: string;
}

/** Exit selection for `connect()`. An all-unset query picks the first cross-checked exit. */
export interface ExitQuery {
  /** Exact exit Ed25519 pubkey (64-hex), matching the warrend IPC connect message. */
  exitPubkeyHex?: string;
  /** ISO 3166-1 alpha-2 country filter. */
  country?: string;
  /** City filter. */
  city?: string;
}

/**
 * Multihop **entry** hop selection for `connect()`: which country/city the
 * circuit enters the Warren fleet through. The entry is always a node
 * distinct from the exit (unlinkability rule); a query only matching the
 * exit's own node fails the connect rather than silently degrading.
 */
export interface EntryQuery {
  /** ISO 3166-1 alpha-2 country filter. */
  country?: string;
  /** City filter. */
  city?: string;
}

/** Per-connect knobs. */
export interface ConnectOptions {
  /** Exit selection; omit to pick the first cross-checked exit. */
  selector?: ExitQuery;
  /**
   * Multihop entry selection. Omit to keep the default circuit (the exit's
   * own co-located relay). Ignored when failover candidates are set.
   */
  entrySelector?: EntryQuery;
  /**
   * Prioritized exit pubkey candidates (64-hex each) for failover. When
   * non-empty, `selector` is ignored and the self-healing datapath is always
   * used (failover needs it).
   */
  failoverExitPubkeyHexes?: string[];
  /** Also bind a local HTTP proxy (CONNECT, and plain `http://` forwarding) alongside SOCKS5. */
  httpProxy?: boolean;
  /**
   * Resolve DNS over the tunnel at this IPv4 address instead of the exit
   * gateway forwarder. Needed for an exit that runs no DNS forwarder.
   */
  dnsServer?: string;
  /**
   * Self-healing datapath that keeps the local listeners stable across
   * reconnects (default `true`, the recommended path). `false` uses the
   * one-shot datapath instead, which additionally exposes live `metrics()`
   * and an async, grant-awaiting `forwardPort()` (the self-healing datapath
   * tracks no per-session metrics upstream, and its forwarded ports establish
   * in the background instead of awaiting the grant).
   */
  supervised?: boolean;
}

/**
 * The bound proxy listener addresses returned by `connect()`, and the
 * credentials every client of them must present (RFC 1929 on SOCKS5,
 * `Proxy-Authorization: Basic` on HTTP): the listeners refuse any client
 * without them. The password is a per-session secret; keep it out of logs,
 * argv and anything another local account can read.
 */
export interface ConnectEndpoints {
  /** The SOCKS5 listener address (`ip:port`). */
  socks5: string;
  /** The HTTP proxy listener address, if `httpProxy` was requested. */
  http?: string;
  /** The username clients present. */
  username: string;
  /** The password clients present. */
  password: string;
}

/**
 * A point-in-time snapshot of the multihop session counters. Only available
 * on the one-shot datapath (`connect({ supervised: false })`); `null` on the
 * self-healing datapath (the engine does not currently instrument it with
 * live counters) or while not connected.
 */
export interface MetricsSnapshot {
  /** Total inner IP bytes sealed and sent. */
  bytesSent: number;
  /** Total inner IP bytes received and opened. */
  bytesRecv: number;
  /** Total IP packets sent. */
  packetsSent: number;
  /** Total IP packets received. */
  packetsRecv: number;
  /** Total DAITA cover-traffic frames sent. */
  coverPacketsSent: number;
  /** Current HPKE epoch (rotates on rekey). */
  epoch: number;
  /** Seconds since the session was established. */
  uptimeSecs: number;
}

/** Transport selector for a forwarded port. */
export type MapProtoJs = 'Tcp' | 'Udp';

/**
 * Why the self-healing supervisor gave up (state `"failed"` with a definitive
 * cause), mirroring the engine's `FatalCause`. A present cause means no redial
 * or other exit will help, so stop retrying and tell the user; a `"failed"`
 * reached by transient-retry exhaustion carries none. Read via
 * `WarrenProxy.fatalCause`.
 */
export type FatalCauseJs = 'NotAuthorized' | 'DeviceLimit' | 'PolicyRefused';

/** A forwarded tunnel-side port (see `WarrenProxy.forwardPort`). */
export declare class WarrenForwardedPort {
  /** The local internal port being forwarded. */
  get internalPort(): number;
  /**
   * The external port remote peers reach the app on, or `null` if not yet
   * granted (self-healing datapath) or after `release()`.
   */
  externalPort(): Promise<number | null>;
  /** Releases the forward. Idempotent: a second call is a no-op. */
  release(): Promise<void>;
}

/** Native binding surface of the Warren proxy datapath (napi-rs). */
export declare class WarrenProxy {
  /**
   * Builds a client from a BIP39 mnemonic, the API base URL and the pinned
   * server key (64-char hex), plus optional builder knobs.
   */
  constructor(
    mnemonic: string,
    apiBase: string,
    serverPubkeyPin: string,
    options?: WarrenProxyOptions | null,
  );

  /** The signer's SS58 `wb...` address. */
  get address(): string;

  /**
   * Registers (or replaces) the state-change callback for future
   * `connect()` calls: called with a lifecycle state string on every
   * transition (`"connecting"`, `"connected"`, `"reconnecting"`,
   * `"draining"`, `"failed"` on the self-healing datapath; `"connected"` /
   * `"disconnected"` on the one-shot datapath). Call before `connect()`; it
   * has no effect on an already-running session. Pass `null` to stop
   * reporting.
   */
  onState(callback: ((state: string) => void) | null): void;

  /**
   * Brings up a real multihop tunnel and local proxy listener(s); resolves
   * with the bound address(es). Rejects if a connect is already in flight or
   * a session is already live, and after `shutdown()`. A `shutdown()` racing
   * an in-flight connect is honoured fail-closed: the tunnel is torn down
   * instead of ever being handed back.
   */
  connect(options?: ConnectOptions | null): Promise<ConnectEndpoints>;

  /** Tears the tunnel down (fail-closed). Idempotent. */
  shutdown(): Promise<void>;

  /** A snapshot of the datapath's live counters; see `MetricsSnapshot`. */
  metrics(): Promise<MetricsSnapshot | null>;

  /**
   * The definitive cause the self-healing supervisor stopped on, or `null`
   * while still healing, on transient-retry exhaustion, or on the one-shot
   * datapath. Read it when the state callback reports `"failed"`: a present
   * cause means retrying is futile (expired subscription, device limit, opaque
   * policy refusal), so stop and tell the user.
   */
  fatalCause(): Promise<FatalCauseJs | null>;

  /**
   * Proves live egress THROUGH the tunnel: the engine's SOCKS5 egress-proof (the
   * listener proves it holds the session's credentials, then a bounded
   * authenticated CONNECT to `1.1.1.1:443` goes through it). Resolves when egress
   * is proven; rejects when it is not (or before `connect()`), so a caller can
   * fail closed instead of trusting a tunnel that silently drops traffic.
   */
  verifyEgress(): Promise<void>;

  /**
   * Forwards a tunnel-side port: asks the exit to map `internalPort` via
   * NAT-PMP and relays inbound connections to `localTarget` (`ip:port`).
   * Needs an exit that runs a NAT-PMP gateway; not every exit does.
   */
  forwardPort(
    proto: MapProtoJs,
    internalPort: number,
    localTarget: string,
  ): Promise<WarrenForwardedPort>;
}
