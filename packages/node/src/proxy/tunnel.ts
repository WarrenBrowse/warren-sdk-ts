import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Tunnel lifecycle states reported by {@link ProxyTunnelOptions.onState}. */
export type ProxyState =
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'draining'
  | 'failed'
  | 'disconnected';

/** Options for a {@link ProxyTunnel}. */
export interface ProxyTunnelOptions {
  /** BIP39 mnemonic of a subscribed account. Used at runtime; never logged or stored. */
  mnemonic: string;
  /** API base URL, e.g. `https://api.warrenbrowse.com`. */
  apiBase: string;
  /** Pinned discovery server public key (64-char hex). */
  serverPubkeyPin: string;
  /** Anti-censorship fallback hostnames tried when the primary host is unreachable. */
  alternativeHosts?: string[];
  /** Offline multihop-directory ROOT Ed25519 pubkey pin (64-char hex). */
  multihopRootPinHex?: string;
  /** Enables the DAITA uplink traffic-analysis defense on multihop tunnels. */
  daita?: boolean;
  /** Pins DAITA to a named curated-pool machine; implies `daita`. */
  daitaMachine?: string;
  /** Requests a dual-stack IPv6 allocation from exits that grant one. */
  requestIpv6?: boolean;
  /**
   * Directory persisting the anti-rollback generation floors and the TOFU
   * server pin across restarts. Without it they live in memory only.
   */
  stateDir?: string;
  /** Called on every tunnel lifecycle transition. Register before `connect()`. */
  onState?: (state: ProxyState) => void;
  /**
   * Supplies the native datapath binding instead of loading the built addon.
   * The DI seam the warrend client exposes via `connectFactory`: used to drive
   * the facade with a fake in tests, or to embed a custom binding. Omit for
   * normal use (the real napi addon is loaded).
   */
  nativeFactory?: () => NativeWarrenProxy;
}

/** Exit selection for {@link ProxyTunnel.connect}. All-unset picks the first cross-checked exit. */
export interface ProxyExitQuery {
  /** Exact exit Ed25519 pubkey (64-char hex), as in the warrend IPC connect message. */
  exitPubkeyHex?: string;
  /** ISO 3166-1 alpha-2 country filter. */
  country?: string;
  /** City filter. */
  city?: string;
}

/**
 * Multihop **entry** hop selection for {@link ProxyTunnel.connect}: which
 * country/city the circuit enters the Warren fleet through. The entry is
 * always a node distinct from the exit (unlinkability rule); a query only
 * matching the exit's own node fails the connect rather than degrading.
 */
export interface ProxyEntryQuery {
  /** ISO 3166-1 alpha-2 country filter. */
  country?: string;
  /** City filter. */
  city?: string;
}

/** Per-connect options for {@link ProxyTunnel.connect}. */
export interface ProxyConnectOptions {
  /** Exit selection; omit to pick the first cross-checked exit. */
  selector?: ProxyExitQuery;
  /**
   * Multihop entry selection. Omit to keep the default circuit (the exit's
   * own co-located relay). Ignored when failover candidates are set.
   */
  entrySelector?: ProxyEntryQuery;
  /**
   * Prioritized exit pubkey candidates (64-char hex each) for failover. When
   * non-empty, `selector` is ignored and the self-healing datapath is used.
   */
  failoverExitPubkeyHexes?: string[];
  /** Also bind a local HTTP proxy (CONNECT, and plain `http://` forwarding) alongside SOCKS5. */
  httpProxy?: boolean;
  /** Resolve DNS over the tunnel at this IPv4 address instead of the exit gateway. */
  dnsServer?: string;
  /**
   * Self-healing datapath keeping the local listeners stable across
   * reconnects (default true). `false` selects the one-shot datapath, which
   * additionally exposes live {@link ProxyTunnel.metrics} and a
   * grant-awaiting {@link ProxyTunnel.forwardPort}.
   */
  supervised?: boolean;
}

/**
 * Local proxy endpoints a {@link ProxyTunnel} exposes once connected, and the
 * credentials every client of them must present (RFC 1929 on SOCKS5,
 * `Proxy-Authorization: Basic` on HTTP): the listeners refuse any client
 * without them, since every account and process on the machine can reach a
 * loopback port. The password is fresh per session; keep it out of logs, argv
 * and anything another local account can read.
 */
export interface ProxyEndpoints {
  /** SOCKS5 listen address, e.g. `127.0.0.1:1080`. */
  socks5: string;
  /** HTTP proxy listen address, present when `httpProxy` was requested. */
  http?: string;
  /** The username clients present. */
  username: string;
  /** The password clients present. */
  password: string;
}

/** A point-in-time snapshot of the tunnel counters (one-shot datapath only). */
export interface ProxyMetrics {
  bytesSent: number;
  bytesRecv: number;
  packetsSent: number;
  packetsRecv: number;
  coverPacketsSent: number;
  epoch: number;
  uptimeSecs: number;
}

/** Transport selector for {@link ProxyTunnel.forwardPort}. */
export type ProxyPortProto = 'Tcp' | 'Udp';

/**
 * Why the self-healing supervisor gave up: a `'failed'` state carrying a
 * definitive cause, mirroring the engine's `FatalCause` across the boundary.
 * The engine owns this classification; the client maps, it never re-decides.
 *
 * A present cause means retrying is futile and no other exit resolves it, so a
 * consumer must STOP its reconnect loop and surface an actionable message
 * instead of looping `'reconnecting'` forever. A `'failed'` reached by mere
 * transient-retry exhaustion carries no cause ({@link ProxyTunnel.fatalCause}
 * returns `null`).
 */
export type ProxyFatalCause =
  /** No active subscription, or not in the exit allowlist: provision/renew. */
  | 'NotAuthorized'
  /** The account already holds its maximum simultaneous devices. */
  | 'DeviceLimit'
  /** Opaque policy refusal: definitive, specific reason unknown to the client. */
  | 'PolicyRefused';

/**
 * Stable error codes carried by {@link WarrenProxyError}. The native codes
 * mirror the sibling SDKs' sealed error hierarchy; `unavailable` is the
 * TS-side "addon missing / failed to load" case, and `outdated` an addon built
 * from another SDK than this facade (see {@link NATIVE_BINDING_ABI}).
 */
export type WarrenProxyErrorCode =
  | 'identity'
  | 'api'
  | 'discovery'
  | 'tunnel'
  | 'config'
  | 'egress'
  | 'unsupported'
  | 'unavailable'
  | 'outdated';

const NATIVE_CODES: readonly WarrenProxyErrorCode[] = [
  'identity',
  'api',
  'discovery',
  'tunnel',
  'config',
  'egress',
  'unsupported',
];

/** Thrown when the native datapath addon is missing or a datapath call fails. */
export class WarrenProxyError extends Error {
  readonly code: WarrenProxyErrorCode;

  constructor(code: WarrenProxyErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'WarrenProxyError';
    this.code = code;
  }
}

/**
 * Maps a native rejection (`"<kind>: message"`, redacted at the FFI boundary)
 * to a typed {@link WarrenProxyError}. Unrecognized shapes become `tunnel`.
 */
function mapNativeError(cause: unknown): WarrenProxyError {
  const raw = cause instanceof Error ? cause.message : String(cause);
  const split = raw.indexOf(': ');
  if (split > 0) {
    const kind = raw.slice(0, split) as WarrenProxyErrorCode;
    if (NATIVE_CODES.includes(kind)) {
      return new WarrenProxyError(kind, raw.slice(split + 2), { cause });
    }
  }
  return new WarrenProxyError('tunnel', 'native datapath call failed', { cause });
}

/**
 * Shape of a native forwarded port. Exported so an embedder or test can supply
 * a {@link ProxyTunnelOptions.nativeFactory}; not needed for normal use.
 */
export interface NativeForwardedPort {
  readonly internalPort: number;
  externalPort(): Promise<number | null>;
  release(): Promise<void>;
}
/**
 * Shape of the native datapath binding. Exported so an embedder or test can
 * supply a {@link ProxyTunnelOptions.nativeFactory} (the same DI seam the
 * warrend client exposes via its `connectFactory`); not needed for normal use.
 */
export interface NativeWarrenProxy {
  readonly address: string;
  onState(callback: ((state: string) => void) | null): void;
  connect(options?: object | null): Promise<ProxyEndpoints>;
  shutdown(): Promise<void>;
  metrics(): Promise<ProxyMetrics | null>;
  fatalCause(): Promise<ProxyFatalCause | null>;
  verifyEgress(): Promise<void>;
  forwardPort(
    proto: ProxyPortProto,
    internalPort: number,
    localTarget: string,
  ): Promise<NativeForwardedPort>;
}
interface NativeBinding {
  bindingAbi(): number;
  WarrenProxy: new (
    mnemonic: string,
    apiBase: string,
    serverPubkeyPin: string,
    options?: object | null,
  ) => NativeWarrenProxy;
}

const here = dirname(fileURLToPath(import.meta.url));
// Resolve the native loader for both the built layout (dist/ -> ../native) and
// the source layout used by tests (src/proxy -> ../../native).
const NATIVE_CANDIDATES = [
  join(here, '..', 'native', 'warren-napi', 'index.cjs'),
  join(here, '..', '..', 'native', 'warren-napi', 'index.cjs'),
];

/**
 * The binding JS surface this facade reads, which the addon reports through
 * `bindingAbi()` (`BINDING_ABI` in `native/warren-napi/src/lib.rs`). Bump both
 * together whenever a field the facade reads changes.
 */
export const NATIVE_BINDING_ABI = 1;

/** Whether the native datapath can carry a tunnel: built and matching this facade. */
export type ProxyDatapathStatus = 'ready' | 'missing' | 'outdated';

/**
 * Reads a loaded binding against {@link NATIVE_BINDING_ABI}. The addon is built
 * outside `pnpm build`, so a checkout can hold one from an older SDK, whose
 * objects lack fields this facade relies on: that is `outdated`, and so is an
 * addon that predates the ABI report altogether.
 */
export function nativeBindingStatus(binding: unknown): Exclude<ProxyDatapathStatus, 'missing'> {
  const report = (binding as { bindingAbi?: unknown } | null)?.bindingAbi;
  return typeof report === 'function' && report() === NATIVE_BINDING_ABI ? 'ready' : 'outdated';
}

let cachedBinding: NativeBinding | undefined;

/** Whether the native datapath addon actually loads on this platform/build. */
export function isProxyDatapathAvailable(): boolean {
  return proxyDatapathStatus() === 'ready';
}

/** Whether the native datapath addon is built, and built from this SDK. */
export function proxyDatapathStatus(): ProxyDatapathStatus {
  try {
    loadNative();
    return 'ready';
  } catch (error) {
    return error instanceof WarrenProxyError && error.code === 'outdated' ? 'outdated' : 'missing';
  }
}

function loadNative(): NativeBinding {
  if (cachedBinding) return cachedBinding;
  const require = createRequire(import.meta.url);
  for (const path of NATIVE_CANDIDATES) {
    if (existsSync(path)) {
      let binding: unknown;
      try {
        binding = require(path);
      } catch (cause) {
        throw new WarrenProxyError('unavailable', 'failed to load the native datapath addon', {
          cause,
        });
      }
      if (nativeBindingStatus(binding) !== 'ready') {
        throw new WarrenProxyError(
          'outdated',
          'the native datapath addon was built from another SDK version; rebuild packages/node/native/warren-napi',
        );
      }
      cachedBinding = binding as NativeBinding;
      return cachedBinding;
    }
  }
  throw new WarrenProxyError(
    'unavailable',
    'native proxy datapath unavailable on this platform/build; build packages/node/native/warren-napi or install a prebuilt',
  );
}

/** A forwarded tunnel-side port; see {@link ProxyTunnel.forwardPort}. */
export class ProxyForwardedPort {
  private readonly native: NativeForwardedPort;

  constructor(native: NativeForwardedPort) {
    this.native = native;
  }

  /** The local internal port being forwarded. */
  get internalPort(): number {
    return this.native.internalPort;
  }

  /**
   * The external port remote peers reach the app on, or `null` if not yet
   * granted (self-healing datapath) or after {@link release}.
   */
  async externalPort(): Promise<number | null> {
    try {
      return await this.native.externalPort();
    } catch (cause) {
      throw mapNativeError(cause);
    }
  }

  /** Releases the forward. Idempotent. */
  async release(): Promise<void> {
    try {
      await this.native.release();
    } catch (cause) {
      throw mapNativeError(cause);
    }
  }
}

/**
 * Non-root proxy datapath: a real Warren multihop tunnel exposed as a local
 * SOCKS5 (and optionally HTTP) proxy that admits only clients presenting the
 * session's credentials, backed by the native engine (napi-rs). One instance
 * is one session; {@link shutdown} tears it down (fail-closed, including a
 * shutdown racing an in-flight connect).
 *
 * The mnemonic is passed to native code once and never retained or logged in TS.
 */
export class ProxyTunnel {
  private readonly native: NativeWarrenProxy;

  private constructor(native: NativeWarrenProxy) {
    this.native = native;
  }

  /** Builds a tunnel client. Throws {@link WarrenProxyError} if the native addon is unavailable. */
  static create(options: ProxyTunnelOptions): ProxyTunnel {
    const { mnemonic, apiBase, serverPubkeyPin, onState, nativeFactory, ...knobs } = options;
    let native: NativeWarrenProxy;
    if (nativeFactory) {
      try {
        native = nativeFactory();
      } catch (cause) {
        throw mapNativeError(cause);
      }
    } else {
      // loadNative() throws an already-typed `unavailable` WarrenProxyError;
      // keep it OUTSIDE the try so it propagates as-is instead of being
      // re-wrapped to a generic `tunnel` code.
      const { WarrenProxy } = loadNative();
      try {
        native = new WarrenProxy(
          mnemonic,
          apiBase,
          serverPubkeyPin,
          Object.keys(knobs).length > 0 ? knobs : null,
        );
      } catch (cause) {
        throw mapNativeError(cause);
      }
    }
    if (onState) native.onState((state) => onState(state as ProxyState));
    return new ProxyTunnel(native);
  }

  /** The signer's SS58 `wb...` address. */
  get address(): string {
    return this.native.address;
  }

  /** Brings up the tunnel and the local proxy listener(s); resolves with their endpoints and credentials. */
  async connect(options?: ProxyConnectOptions): Promise<ProxyEndpoints> {
    try {
      return await this.native.connect(options ?? null);
    } catch (cause) {
      throw mapNativeError(cause);
    }
  }

  /** Tears the tunnel down (fail-closed). Idempotent. */
  async shutdown(): Promise<void> {
    try {
      await this.native.shutdown();
    } catch (cause) {
      throw mapNativeError(cause);
    }
  }

  /**
   * A live counters snapshot, or `null` on the self-healing datapath (not
   * instrumented upstream) and while not connected.
   */
  async metrics(): Promise<ProxyMetrics | null> {
    try {
      return await this.native.metrics();
    } catch (cause) {
      throw mapNativeError(cause);
    }
  }

  /**
   * The definitive cause the self-healing supervisor stopped on, or `null`
   * while still healing, on transient-retry exhaustion, or on the one-shot
   * datapath. Read it when {@link ProxyTunnelOptions.onState} reports
   * `'failed'`: a present cause means retrying is futile (expired subscription,
   * device limit, opaque policy refusal), so a consumer must STOP its reconnect
   * loop and tell the user instead of looping `'reconnecting'` forever.
   */
  async fatalCause(): Promise<ProxyFatalCause | null> {
    try {
      return await this.native.fatalCause();
    } catch (cause) {
      throw mapNativeError(cause);
    }
  }

  /**
   * Proves live egress THROUGH the tunnel: the engine's SOCKS5 egress-proof (the
   * listener proves it holds the session's credentials, then a bounded
   * authenticated CONNECT to `1.1.1.1:443` goes through it). Resolves when egress
   * is proven; rejects with a {@link WarrenProxyError} when it is not (or before
   * {@link ProxyTunnel.connect}), so a consumer can fail closed instead of
   * trusting a tunnel that silently drops traffic.
   */
  async verifyEgress(): Promise<void> {
    try {
      await this.native.verifyEgress();
    } catch (cause) {
      throw mapNativeError(cause);
    }
  }

  /**
   * Forwards a tunnel-side port: asks the exit to map `internalPort` via
   * NAT-PMP and relays inbound connections to `localTarget` (`ip:port`).
   * Needs an exit that runs a NAT-PMP gateway.
   */
  async forwardPort(
    proto: ProxyPortProto,
    internalPort: number,
    localTarget: string,
  ): Promise<ProxyForwardedPort> {
    try {
      return new ProxyForwardedPort(
        await this.native.forwardPort(proto, internalPort, localTarget),
      );
    } catch (cause) {
      throw mapNativeError(cause);
    }
  }
}
