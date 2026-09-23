import { hardenBrowserLeaks, releaseBrowserLeaks } from './leaks.js';
import {
  DEFAULT_HOST_NAME,
  EXTENSION_PROTOCOL_VERSION,
  type ExtensionEndpoints,
  type ExtensionEntryQuery,
  type ExtensionExitLocation,
  type ExtensionExitQuery,
  type ExtensionProxyAuth,
  type ExtensionVpnState,
  type HostRequest,
  type HostResponse,
  parseHostMessage,
} from './protocol.js';
import {
  DEFAULT_SPLIT,
  FAIL_CLOSED_PROXY,
  type SplitTunnelConfig,
  buildChromiumLockdownValue,
  buildChromiumProxyValue,
  buildFirefoxProxyValue,
  shouldTunnelHost,
} from './split.js';

/** Discriminator for {@link WarrenExtensionError}. */
export type WarrenExtensionErrorCode =
  | 'host_unavailable'
  | 'protocol'
  | 'host'
  | 'already_connected'
  | 'not_connected'
  | 'proxy_uncontrollable'
  | 'private_browsing_required';

/** A typed extension-side error. Host messages are already redacted by the host. */
export class WarrenExtensionError extends Error {
  readonly code: WarrenExtensionErrorCode;
  /** The host's own error code when `code === 'host'` (e.g. `api`, `tunnel`). */
  readonly hostCode?: string;

  constructor(code: WarrenExtensionErrorCode, message: string, hostCode?: string) {
    super(message);
    this.name = 'WarrenExtensionError';
    this.code = code;
    if (hostCode !== undefined) this.hostCode = hostCode;
  }
}

/** A `chrome.types.ChromeSetting`-shaped controllable browser setting. */
export interface ChromeSettingLike {
  get?(details: { incognito?: boolean }): unknown;
  set(details: { value: unknown; scope?: string }): unknown;
  clear(details: { scope?: string }): unknown;
}

/** A Firefox `proxy.onRequest` event, used for per-host `only` split tunneling. */
export interface ProxyOnRequestLike {
  addListener(callback: (request: { url: string }) => unknown, filter?: { urls: string[] }): void;
  removeListener(callback: (request: { url: string }) => unknown): void;
}

/** The subset of the chrome extension API the client drives (injectable in tests). */
export interface ChromeLike {
  proxy: {
    settings: ChromeSettingLike;
    /** Firefox only: per-request proxy resolution. */
    onRequest?: ProxyOnRequestLike;
  };
  privacy: {
    network: {
      webRTCIPHandlingPolicy: ChromeSettingLike;
      /** DNS prefetcher toggle; resolves names locally even under SOCKS5. */
      networkPredictionEnabled?: ChromeSettingLike;
    };
  };
  runtime: {
    connectNative(name: string): NativePort;
    /** Firefox only; its presence is the platform auto-detection signal. */
    getBrowserInfo?(): unknown;
  };
  /** Firefox only: private-browsing access gate for proxy.settings.set. */
  extension?: {
    isAllowedIncognitoAccess(): Promise<boolean>;
  };
}

/** What `proxy.settings.get` answers: the effective value and who controls it. */
interface ProxySettingDetails {
  value?: unknown;
  levelOfControl?: string;
}

/** The browser family, driving the proxy-settings dialect. */
export type ExtensionPlatform = 'chromium' | 'firefox';

/** A `chrome.runtime.connectNative` port (Chrome frames the JSON itself). */
export interface NativePort {
  postMessage(message: unknown): void;
  disconnect(): void;
  onMessage: { addListener(callback: (message: unknown) => void): void };
  onDisconnect: { addListener(callback: () => void): void };
}

/** Options for {@link WarrenBrowserVpn}. */
export interface WarrenBrowserVpnOptions {
  /** Native messaging host name. Defaults to {@link DEFAULT_HOST_NAME}. */
  hostName?: string;
  /** The chrome API. Defaults to the global `chrome`; injectable for tests. */
  chrome?: ChromeLike;
  /**
   * Proxy-settings dialect. Defaults to auto-detection
   * (`runtime.getBrowserInfo` exists only in Firefox).
   */
  platform?: ExtensionPlatform;
  /** Called on every tunnel state transition relayed by the host. */
  onState?: (state: ExtensionVpnState) => void;
}

/** Options for {@link WarrenBrowserVpn.connect}. */
export interface BrowserVpnConnectOptions {
  /**
   * The account mnemonic from the unlocked wallet. Relayed to the local host
   * for the datapath; never persisted here nor sent to any page or the network.
   */
  mnemonic: string;
  selector?: ExtensionExitQuery;
  /** Multihop entry-hop selection; omit for the default circuit. */
  entrySelector?: ExtensionEntryQuery;
  httpProxy?: boolean;
  /** Per-site routing. Defaults to tunneling all traffic. */
  split?: SplitTunnelConfig;
  /** Enables the DAITA uplink traffic-analysis defense on the tunnel. */
  daita?: boolean;
}

/** How long an explicit disconnect waits for the host to acknowledge. */
const HOST_DISCONNECT_TIMEOUT_MS = 3000;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out')), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function globalChrome(): ChromeLike {
  const c = (globalThis as { chrome?: ChromeLike }).chrome;
  if (!c) {
    throw new WarrenExtensionError(
      'host_unavailable',
      'no chrome extension API in this environment',
    );
  }
  return c;
}

/** Whether a host answer carries the credentials its listeners demand. */
function listenerAuth(auth: unknown): ExtensionProxyAuth | undefined {
  if (typeof auth !== 'object' || auth === null) return undefined;
  const { username, password } = auth as Partial<ExtensionProxyAuth>;
  if (typeof username !== 'string' || username.length === 0) return undefined;
  if (typeof password !== 'string' || password.length === 0) return undefined;
  return { username, password };
}

/**
 * Browser-scope, non-root VPN control: drives the local Warren native host
 * over native messaging and routes the whole browser through the host's local
 * proxy via `chrome.proxy`: its HTTP listener on Chromium, which cannot
 * authenticate to a SOCKS5 proxy, and its SOCKS5 listener on Firefox, whose
 * `proxy.onRequest` answers carry the credentials.
 *
 * Both listeners demand the credentials the host minted for this tunnel. They
 * live in this object's memory for as long as that host lives, and
 * {@link forListener} hands them only to a challenge from one of its
 * listeners: the Chromium background answers the listener's `407` with them
 * (see `attachChromiumProxyAuth`).
 *
 * Fail-closed policy: once connected, the proxy settings are only ever removed
 * by an explicit {@link disconnect}. If the host dies, the port it released is
 * anyone's to bind, so the browser never stays pointed at it: Chromium moves
 * onto the lockdown block (a loopback proxy nothing answers), Firefox's
 * per-request handler refuses the dead listener, `onState('failed')` fires and
 * the {@link onHostLost} listeners hear it. A failed connect leaves the browser
 * as it found it: a routing this extension already held (a lockdown, or the
 * block a dead host left) is put back, never replaced by a direct route.
 *
 * Requires manifest permissions: `proxy`, `privacy`, `nativeMessaging`.
 */
export class WarrenBrowserVpn {
  private readonly hostName: string;
  private readonly chromeApi: ChromeLike | undefined;
  private readonly onState: ((state: ExtensionVpnState) => void) | undefined;

  private port: NativePort | undefined;
  private portDead = false;
  private proxied = false;
  /** Whether the host that built the current tunnel is still attached. A dead
   * host takes its tunnel with it, while {@link proxied} keeps the browser
   * pointed at the corpse (fail-closed). */
  private tunnelUp = false;
  private endpoints: ExtensionEndpoints | undefined;
  /** The credentials of the live host's listeners; dropped with the host. */
  private auth: ExtensionProxyAuth | undefined;
  private connecting = false;
  /** Set for the length of an explicit {@link disconnect}, whose host may exit
   * on its own once it has answered: that exit is not a lost host. */
  private releasing = false;
  private readonly hostLostListeners: Array<() => void> = [];
  private nextId = 1;
  private onRequestHandler: ((request: { url: string }) => unknown) | undefined;
  private readonly pending = new Map<
    number,
    { resolve: (r: HostResponse) => void; reject: (e: Error) => void }
  >();

  private readonly platformOption: ExtensionPlatform | undefined;

  constructor(options: WarrenBrowserVpnOptions = {}) {
    this.hostName = options.hostName ?? DEFAULT_HOST_NAME;
    this.chromeApi = options.chrome;
    this.platformOption = options.platform;
    this.onState = options.onState;
  }

  private get platform(): ExtensionPlatform {
    if (this.platformOption) return this.platformOption;
    return typeof this.chrome.runtime.getBrowserInfo === 'function' ? 'firefox' : 'chromium';
  }

  private get chrome(): ChromeLike {
    return this.chromeApi ?? globalChrome();
  }

  /**
   * Whether the browser's proxy settings are still routed at the tunnel. The
   * client is fail-closed (only an explicit {@link disconnect} clears the
   * settings), so while this is true a dead host or failed tunnel blackholes
   * traffic instead of leaking it: the phase reduction renders that as
   * `blocked`, not `exposed`.
   */
  isProxied(): boolean {
    return this.proxied;
  }

  /**
   * The credentials of the live tunnel's listener at `listener` (`host:port`),
   * or `undefined` when no live host owns that address: a listener of a dead
   * host, or a process that took its port over, gets nothing.
   */
  forListener(listener: string): ExtensionProxyAuth | undefined {
    const endpoints = this.endpoints;
    if (!this.auth || !endpoints) return undefined;
    return listener === endpoints.http || listener === endpoints.socks5
      ? { ...this.auth }
      : undefined;
  }

  /**
   * Registers `listener` for the loss of the host that carried the live
   * tunnel, without an explicit {@link disconnect}. By the time it runs,
   * Chromium already stalls on the lockdown block; the listener decides what
   * protection the product holds next.
   */
  onHostLost(listener: () => void): void {
    this.hostLostListeners.push(listener);
  }

  /**
   * Opens the host, handshakes, brings the tunnel up and routes the browser
   * through it. Resolves with the local proxy endpoints.
   */
  async connect(options: BrowserVpnConnectOptions): Promise<ExtensionEndpoints> {
    if (this.connecting) throw new WarrenExtensionError('already_connected', 'connect in flight');
    // A tunnel whose host died is gone: reconnecting over its held routing is
    // how the browser gets back, so only a live tunnel refuses a second connect.
    if (this.tunnelUp) throw new WarrenExtensionError('already_connected', 'already connected');
    this.connecting = true;
    let hardened = false;
    let before: ProxySettingDetails | undefined;
    let leaksHeld = false;
    // A handler of a tunnel whose host died is part of the routing held until
    // the new one is in place: removed on success, kept on failure.
    const heldHandler = this.onRequestHandler;
    this.onRequestHandler = undefined;
    try {
      // Fail early: a set() while another extension controls the proxy would
      // silently do nothing, leaving a live tunnel with no browser routed
      // through it. Most-recently-installed extension wins in Chromium.
      before = await this.assertProxyControl([
        'controllable_by_this_extension',
        'controlled_by_this_extension',
      ]);
      leaksHeld = await this.holdsLeakHardening();
      if (this.platform === 'firefox') {
        // Firefox rejects proxy.settings.set without private-browsing access,
        // which only the user can grant; surface it before dialing.
        const allowed = await this.chrome.extension?.isAllowedIncognitoAccess();
        if (allowed === false) {
          throw new WarrenExtensionError(
            'private_browsing_required',
            'Firefox requires private-browsing access to control proxy settings',
          );
        }
        // proxy.settings cannot carry the listener's credentials: only a
        // per-request answer can.
        if (!this.chrome.proxy.onRequest) {
          throw new WarrenExtensionError(
            'proxy_uncontrollable',
            'this browser cannot route requests one by one',
          );
        }
      }
      const hello = await this.request({ type: 'hello', protocol: EXTENSION_PROTOCOL_VERSION });
      if (hello.type !== 'hello' || hello.protocol !== EXTENSION_PROTOCOL_VERSION) {
        throw new WarrenExtensionError('protocol', 'host speaks an unsupported protocol version');
      }
      const httpProxy = this.platform === 'chromium' ? true : options.httpProxy;
      const res = await this.request({
        type: 'connect',
        mnemonic: options.mnemonic,
        ...(options.selector ? { selector: options.selector } : {}),
        ...(options.entrySelector ? { entrySelector: options.entrySelector } : {}),
        ...(httpProxy !== undefined ? { httpProxy } : {}),
        ...(options.daita !== undefined ? { daita: options.daita } : {}),
      });
      if (res.type !== 'connect') {
        throw new WarrenExtensionError('protocol', 'unexpected host response to connect');
      }
      const auth = listenerAuth(res.auth);
      if (!auth) {
        throw new WarrenExtensionError(
          'protocol',
          'the host did not hand over the credentials its listeners demand',
        );
      }
      // Leak hardening BEFORE routing: WebRTC UDP candidates and the DNS
      // prefetcher (which resolves locally even under SOCKS5) must be off
      // before any traffic follows the proxy.
      await hardenBrowserLeaks(this.chrome.privacy.network);
      hardened = true;
      const split = options.split ?? DEFAULT_SPLIT;
      this.assertHostAlive();
      // Held before the browser is pointed at the listener, whose first
      // challenge can come as soon as the routing is set.
      this.endpoints = res.endpoints;
      this.auth = auth;
      await this.applyProxy(res.endpoints, split);
      await this.verifyRouting(split);
      // A host that died meanwhile released the ports just routed to: the
      // failure path puts back what the browser held before.
      this.assertHostAlive();
      this.proxied = true;
      this.tunnelUp = true;
      if (heldHandler) this.chrome.proxy.onRequest?.removeListener(heldHandler);
      return res.endpoints;
    } catch (error) {
      this.endpoints = undefined;
      this.auth = undefined;
      if (hardened) await this.restoreBrowserSettings(before, leaksHeld).catch(() => undefined);
      this.onRequestHandler = heldHandler;
      this.closePort();
      throw error;
    } finally {
      this.connecting = false;
    }
  }

  /** Throws when the host this connect is talking to has gone. */
  private assertHostAlive(): void {
    if (this.portDead) {
      throw new WarrenExtensionError('host_unavailable', 'native messaging host disconnected');
    }
  }

  /**
   * Re-applies the browser routing with new split rules over the live tunnel.
   * The rules live in the browser, not the host, so nothing is torn down and
   * the browser never goes direct in between.
   *
   * @throws {WarrenExtensionError} `not_connected` with no live tunnel, and
   * `proxy_uncontrollable` when the new settings did not take.
   */
  async applySplit(split: SplitTunnelConfig): Promise<void> {
    if (!this.tunnelUp || !this.endpoints) {
      throw new WarrenExtensionError('not_connected', 'no live tunnel to route through');
    }
    // The new routing goes in before the old handler comes out: in between,
    // Firefox runs both, which tunnels the union of the two rule sets.
    const previous = this.onRequestHandler;
    this.onRequestHandler = undefined;
    await this.applyProxy(this.endpoints, split);
    if (previous) this.chrome.proxy.onRequest?.removeListener(previous);
    await this.verifyRouting(split);
  }

  /** A set() that did not take control is a silent no-op: verify it took.
   * Firefox's only mode routes through a handler and sets nothing to verify. */
  private async verifyRouting(split: SplitTunnelConfig): Promise<void> {
    if (this.platform === 'firefox' && split.mode === 'only' && this.onRequestHandler) return;
    await this.assertProxyControl(['controlled_by_this_extension']);
  }

  private async assertProxyControl(
    acceptable: readonly string[],
  ): Promise<ProxySettingDetails | undefined> {
    const get = this.chrome.proxy.settings.get?.bind(this.chrome.proxy.settings);
    if (!get) return undefined;
    const details = (await get({})) as ProxySettingDetails | undefined;
    const level = details?.levelOfControl;
    if (level !== undefined && !acceptable.includes(level)) {
      throw new WarrenExtensionError(
        'proxy_uncontrollable',
        'proxy settings are controlled elsewhere (another extension or enterprise policy)',
      );
    }
    return details;
  }

  /** Whether the WebRTC leak setting is already this extension's (a lockdown
   * or a tunnel whose host died holds it), which a failed connect keeps. */
  private async holdsLeakHardening(): Promise<boolean> {
    const setting = this.chrome.privacy.network.webRTCIPHandlingPolicy;
    const details = (await setting.get?.({})) as ProxySettingDetails | undefined;
    return details?.levelOfControl === 'controlled_by_this_extension';
  }

  /** Undoes a failed connect. What this extension held before (a routing, the
   * leak hardening) is put back as it was; the rest goes back to the browser's
   * defaults, as nothing of ours was protecting it. */
  private async restoreBrowserSettings(
    before: ProxySettingDetails | undefined,
    leaksHeld: boolean,
  ): Promise<void> {
    this.removeOnRequestHandler();
    if (before?.levelOfControl === 'controlled_by_this_extension') {
      await this.chrome.proxy.settings.set({ value: before.value });
    } else {
      await this.chrome.proxy.settings.clear({});
    }
    if (!leaksHeld && before?.levelOfControl !== 'controlled_by_this_extension') {
      await releaseBrowserLeaks(this.chrome.privacy.network);
    }
  }

  private removeOnRequestHandler(): void {
    if (this.onRequestHandler) {
      this.chrome.proxy.onRequest?.removeListener(this.onRequestHandler);
      this.onRequestHandler = undefined;
    }
  }

  private async clearBrowserSettings(): Promise<void> {
    this.removeOnRequestHandler();
    await this.chrome.proxy.settings.clear({});
    await releaseBrowserLeaks(this.chrome.privacy.network);
  }

  /** Asks the host for the current tunnel state. */
  async status(): Promise<{ state: ExtensionVpnState; endpoints?: ExtensionEndpoints }> {
    const res = await this.request({ type: 'status' });
    if (res.type !== 'status') {
      throw new WarrenExtensionError('protocol', 'unexpected host response to status');
    }
    return { state: res.state, ...(res.endpoints ? { endpoints: res.endpoints } : {}) };
  }

  /** Lists the selectable exit locations from the host's verified relay list. */
  async listExits(): Promise<ExtensionExitLocation[]> {
    const res = await this.request({ type: 'exits' });
    if (res.type !== 'exits') {
      throw new WarrenExtensionError('protocol', 'unexpected host response to exits');
    }
    return res.locations;
  }

  /**
   * Fetches the account subscription status. The mnemonic follows the same
   * rules as connect: handed once to the local host to sign, never persisted.
   */
  async account(mnemonic: string): Promise<{ expiresAt: number }> {
    const res = await this.request({ type: 'account', mnemonic });
    if (res.type !== 'account') {
      throw new WarrenExtensionError('protocol', 'unexpected host response to account');
    }
    return { expiresAt: res.expiresAt };
  }

  /**
   * Explicit user disconnect: tears the tunnel down and, only here, removes
   * the proxy settings and restores the WebRTC policy.
   */
  async disconnect(): Promise<void> {
    this.releasing = true;
    try {
      if (this.port && !this.portDead) {
        // Bounded: a host that stops answering must not keep the user's explicit
        // disconnect from restoring direct routing.
        await withTimeout(this.request({ type: 'disconnect' }), HOST_DISCONNECT_TIMEOUT_MS).catch(
          () => undefined,
        );
      }
      await this.clearBrowserSettings();
      this.proxied = false;
    } finally {
      // Even when the settings could not be cleared, the user asked for the
      // tunnel to go: its host is released here, and its later death is not
      // a lost host to block the browser for.
      this.tunnelUp = false;
      this.endpoints = undefined;
      this.auth = undefined;
      this.closePort();
      this.releasing = false;
    }
  }

  private async applyProxy(endpoints: ExtensionEndpoints, split: SplitTunnelConfig): Promise<void> {
    if (this.platform === 'firefox') {
      // The handler carries the listener's credentials, so it routes every
      // mode. The settings below are what holds the browser on the (then
      // refusing) listener if the handler is ever gone; `only` mode cannot be
      // expressed there and has the handler alone.
      this.registerFirefoxOnRequest(endpoints.socks5, split);
      if (split.mode === 'only') return;
      const result = await this.chrome.proxy.settings.set({
        value: buildFirefoxProxyValue(endpoints.socks5, split),
      });
      // Firefox BrowserSetting.set resolves false when the value was not applied.
      if (result === false) {
        throw new WarrenExtensionError(
          'proxy_uncontrollable',
          'proxy settings are controlled elsewhere (another extension or enterprise policy)',
        );
      }
      return;
    }
    if (!endpoints.http) {
      throw new WarrenExtensionError('protocol', 'the host serves no HTTP listener');
    }
    await this.chrome.proxy.settings.set({
      value: buildChromiumProxyValue(endpoints.http, split),
    });
  }

  private registerFirefoxOnRequest(socks5: string, split: SplitTunnelConfig): void {
    const sep = socks5.lastIndexOf(':');
    const listener = {
      type: 'socks',
      host: socks5.slice(0, sep),
      port: Number(socks5.slice(sep + 1)),
    };
    const handler = (request: { url: string }): unknown => {
      const host = new URL(request.url).hostname;
      if (!shouldTunnelHost(host, split)) return { type: 'direct' };
      // Read per request: once the host is gone its port is anyone's to take,
      // and the request stalls instead of reaching it.
      const auth = this.forListener(socks5);
      return auth ? { ...listener, proxyDNS: true, ...auth } : FAIL_CLOSED_PROXY;
    };
    this.onRequestHandler = handler;
    this.chrome.proxy.onRequest?.addListener(handler, { urls: ['<all_urls>'] });
  }

  private openPort(): NativePort {
    if (this.port && !this.portDead) return this.port;
    let port: NativePort;
    try {
      port = this.chrome.runtime.connectNative(this.hostName);
    } catch (cause) {
      throw new WarrenExtensionError(
        'host_unavailable',
        'native messaging host is not installed or refused the connection',
      );
    }
    this.port = port;
    this.portDead = false;
    port.onMessage.addListener((raw) => this.onMessage(raw));
    port.onDisconnect.addListener(() => {
      this.portDead = true;
      // Only the host that built the live tunnel owned the ports the browser
      // is routed at; a host spawned since to report a state owned none.
      const lost = this.tunnelUp && !this.releasing;
      this.tunnelUp = false;
      // The host took its listeners with it: nothing may answer for them now.
      this.auth = undefined;
      const wasProxied = this.proxied;
      for (const [, waiter] of this.pending) {
        waiter.reject(
          new WarrenExtensionError('host_unavailable', 'native messaging host disconnected'),
        );
      }
      this.pending.clear();
      // Fail-closed: this.proxied stays true and the routing stays ours; only
      // an explicit disconnect() sends the browser direct.
      if (lost) this.blockReleasedListener();
      if (wasProxied) this.onState?.('failed');
      if (lost) for (const listener of this.hostLostListeners) listener();
    });
    return port;
  }

  /**
   * Moves Chromium off a dead host's listener: any local process can bind the
   * port it released and would then receive the browser's requests. Firefox
   * needs nothing here, its per-request handler refuses a listener whose host
   * is gone. Best effort: a set that does not take leaves the lost-host
   * listeners to hold the browser.
   */
  private blockReleasedListener(): void {
    if (this.platform !== 'chromium') return;
    try {
      Promise.resolve(
        this.chrome.proxy.settings.set({ value: buildChromiumLockdownValue([]) }),
      ).catch(() => undefined);
    } catch {
      // Same as a set that did not take.
    }
  }

  private onMessage(raw: unknown): void {
    const message = parseHostMessage(raw);
    if (!message) return;
    if ('type' in message && message.type === 'state' && !('id' in message)) {
      this.onState?.(message.state);
      return;
    }
    const response = message as HostResponse;
    const waiter = this.pending.get(response.id);
    if (!waiter) return;
    this.pending.delete(response.id);
    if (response.ok) {
      waiter.resolve(response);
    } else {
      waiter.reject(new WarrenExtensionError('host', response.message, response.code));
    }
  }

  private request(
    // Distributive omit: a plain Omit over the request union would collapse
    // it to the shared keys and drop per-variant fields like `protocol`.
    body: HostRequest extends infer R ? (R extends HostRequest ? Omit<R, 'id'> : never) : never,
  ): Promise<Extract<HostResponse, { ok: true }>> {
    const port = this.openPort();
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, {
        resolve: (r) => resolve(r as Extract<HostResponse, { ok: true }>),
        reject,
      });
      port.postMessage({ id, ...body });
    });
  }

  private closePort(): void {
    if (this.port && !this.portDead) this.port.disconnect();
    this.port = undefined;
    this.portDead = false;
    // A port we close ourselves fires no onDisconnect, so its waiters would
    // hang for good, a stuck connect with them.
    for (const [, waiter] of this.pending) {
      waiter.reject(new WarrenExtensionError('host_unavailable', 'native messaging host closed'));
    }
    this.pending.clear();
  }
}
