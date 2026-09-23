/**
 * Zero-install browser routing: point the WHOLE browser at a remote Warren
 * ingress with nothing installed on the machine, and keep the UI honest about
 * it by reading the browser back as the single source of truth.
 *
 * This module is the client half of warren-core docs 103 (the CONNECT tier) and
 * 104 (the MASQUE and blind-ingress upgrades). It replaces the older
 * `WarrenBrowserProxy`, whose in-memory state did not survive a Manifest V3
 * service-worker teardown: the browser kept routing while the extension reported
 * itself idle, so the user could neither see nor stop the tunnel. Everything
 * here is transport-free and unit-testable; the background wires the real
 * `chrome.*` surface and the credential source.
 *
 * # The one invariant
 *
 * The browser's proxy configuration OUTLIVES the worker. So the worker never
 * trusts its own memory: {@link readChromiumRouting} reads
 * `chrome.proxy.settings` back, and the Firefox path persists a
 * {@link RoutingState} that its `proxy.onRequest` listener reloads on every
 * request. A popup that opens after a teardown therefore learns the truth from
 * the browser, not from a variable that was reset to zero.
 *
 * # Per-browser dialect
 *
 * Chromium takes `proxy.settings` (`fixed_servers`, or a PAC script for
 * per-site `only` mode) and answers the ingress `407` through an async blocking
 * `webRequest.onAuthRequired` provider. Firefox uses `proxy.onRequest`, which
 * carries the credential on the ProxyInfo itself and, since Firefox 146, accepts
 * a `masque` ProxyInfo (a proxy tunnel over QUIC, RFC 9298) with the CONNECT
 * `https` ingress as its failover.
 *
 * # Fail closed
 *
 * A missing credential, a dead ingress or an unreadable store leaves the browser
 * routed and stalling, never falling back to a direct, unprotected route. Only
 * an explicit disconnect restores direct routing.
 *
 * # Lockdown
 *
 * A {@link LockdownState} is the routing a browser holds while its user wants
 * protection and no tier carries it yet (the browser restarted, the wallet is
 * locked, the hour's credential is missing). It stalls every request except the
 * few hosts reconnecting needs, and it persists like any other routing, so a
 * restart or an extension update never opens a direct window.
 */

import { base64urlnopad } from '@scure/base';
import { WarrenExtensionError } from './client.js';
import type { ExtensionProxyAuth } from './protocol.js';
import {
  FAIL_CLOSED_PROXY,
  LOCKDOWN_PROXY,
  type SplitTunnelConfig,
  buildChromiumLockdownValue,
  shouldTunnelHost,
} from './split.js';

export { FAIL_CLOSED_PROXY, buildChromiumLockdownValue };

/** The fixed username the credential rides under; only the password varies. */
export const CREDENTIAL_USERNAME = 'warren';

/**
 * Encodes one pre-minted browser-proxy credential for the wire.
 *
 * The password half of a Basic credential travels through a browser as a
 * string, so the token is base64url-encoded rather than raw; the ingress
 * decodes exactly this. One definition on both sides of the wire.
 */
export function encodeBrowserProxyCredential(token: Uint8Array): string {
  return base64urlnopad.encode(token);
}

/** Hosts that never go through the ingress: the extension must still reach a
 * local host, and loopback has no route through a remote proxy. */
const LOOPBACK_BYPASS = ['localhost', '127.0.0.1'];

/**
 * Where and how the browser reaches a Warren ingress.
 *
 * `https` is the shipped CONNECT tier: TLS over TCP on 443, the exit terminates
 * the CONNECT. `masque` is the Firefox HTTP/3 upgrade (doc 104): the browser
 * tunnels its own QUIC to origins through CONNECT-UDP, and falls back to the
 * `https` ingress for origins without HTTP/3.
 */
export type IngressEndpoint =
  | { kind: 'https'; host: string; port: number }
  | { kind: 'masque'; host: string; port: number; masqueTemplate: string };

/**
 * The routing installed in the browser, persisted so a service-worker teardown
 * cannot lose it. Holds no secret: the credential is never stored here, only
 * fetched fresh from the credential provider when a request needs it.
 */
export interface RoutingState {
  /** `ingress` is the zero-install remote proxy this module drives. */
  readonly tier: 'ingress';
  readonly endpoint: IngressEndpoint;
  readonly split: SplitTunnelConfig;
  /** The exit this routes through, for display. */
  readonly exit: { country: string; city: string };
  /** How many Warren nodes the traffic crosses: 1 for the single-hop CONNECT
   * tier, 2 for the blind-ingress topology (doc 104 § 5). Drives the UI's
   * hop label so a user is never told "multi-hop" for a single hop. */
  readonly hops: 1 | 2;
  /** Unix ms the routing was installed, for diagnostics. */
  readonly installedAt: number;
}

/**
 * The routing held while protection is wanted and no tier carries the browser.
 * Every request stalls except loopback and {@link exempt}, which is exactly
 * what reconnecting needs (the Warren API the background signs against) and
 * never a destination the user browses.
 */
export interface LockdownState {
  readonly tier: 'lockdown';
  /** Hostnames that stay reachable directly, matched exactly. */
  readonly exempt: readonly string[];
  /** Unix ms the lockdown was installed, for diagnostics. */
  readonly installedAt: number;
}

/**
 * The multi-hop tier's routing: the local SOCKS endpoint of the native host's
 * tunnel and the split it applies. Firefox forgets an in-memory `onRequest`
 * handler with the worker, so the persistent listener answers from this record
 * too, and a restart finds the browser pointed at the (now dead) tunnel rather
 * than direct.
 */
export interface MultihopRoutingState {
  readonly tier: 'multihop';
  /** `host:port` of the native host's SOCKS5 proxy. */
  readonly socks5: string;
  readonly split: SplitTunnelConfig;
  /** Unix ms the routing was installed, for diagnostics. */
  readonly installedAt: number;
}

/** Whatever the browser is told to do, persisted across worker teardowns,
 * browser restarts and extension updates. */
export type RoutingRecord = RoutingState | LockdownState | MultihopRoutingState;

/** Yields the credential to present right now, or `undefined` when the store
 * holds none for this epoch. Async because minting and epoch bookkeeping are. */
export interface CredentialProvider {
  current(): Promise<string | undefined>;
}

/** Persists the {@link RoutingRecord} across service-worker teardowns. Backed
 * by durable storage, it also survives a browser restart and an update. */
export interface RoutingStore {
  load(): Promise<RoutingRecord | undefined>;
  save(record: RoutingRecord): Promise<void>;
  clear(): Promise<void>;
}

/** A `chrome.proxy.settings`-shaped surface (promise flavour, MV3). */
export interface ProxySettingsLike {
  get(details: object): Promise<{ value?: unknown; levelOfControl: string }>;
  set(details: { value: unknown; scope?: string }): Promise<void> | void;
  clear(details?: { scope?: string }): Promise<void> | void;
}

/** What `webRequest.onAuthRequired` says about a challenge. */
export interface AuthChallenge {
  isProxy: boolean;
  requestId?: string;
  /** The proxy or server asking, as the browser dialed it. */
  challenger?: { host: string; port: number };
}

/** The `chrome.webRequest` subset used to answer a proxy's `407`. */
export interface WebRequestLike {
  onAuthRequired: {
    addListener(
      listener: (details: AuthChallenge, callback: (response: unknown) => void) => void,
      filter: { urls: string[] },
      extra?: string[],
    ): void;
  };
}

/** The native host's listener credentials, held in memory by the multi-hop
 * tier (`WarrenBrowserVpn` is one). */
export interface LocalProxyAuth {
  /** The credentials of the live session whose listener is at `listener`
   * (`host:port`), or `undefined` when no live session owns that address. */
  forListener(listener: string): ExtensionProxyAuth | undefined;
}

/** Where each proxy's credentials come from. Each answers only the proxy it
 * belongs to: the ingress credential never goes to a loopback listener, and a
 * listener's credentials never leave the machine. */
export interface ProxyAuthSources {
  /** The browser-proxy tier: its credential, and the routing record naming
   * the ingress it may be presented to. */
  ingress?: { credentials: CredentialProvider; routing: RoutingStore };
  /** The multi-hop tier's local listeners. */
  local?: LocalProxyAuth;
}

/** The Firefox `proxy` subset: per-request resolution plus an error signal. */
export interface FirefoxProxyLike {
  onRequest: {
    addListener(listener: (request: { url: string }) => unknown, filter: { urls: string[] }): void;
  };
  onError?: { addListener(listener: (error: unknown) => void): void };
}

/** A `chrome.storage`-shaped area (promise flavour). */
export interface RoutingStorageArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

/** A Firefox ProxyInfo entry, as returned from `proxy.onRequest`. */
export interface FirefoxProxyInfo {
  type: 'https' | 'masque' | 'socks' | 'direct';
  host?: string;
  port?: number;
  masqueTemplate?: string;
  proxyAuthorizationHeader?: string;
  failoverTimeout?: number;
  /** SOCKS only: resolve names at the proxy. */
  proxyDNS?: boolean;
  /** SOCKS only (RFC 1929); Firefox refuses them on the other types. */
  username?: string;
  password?: string;
}

const ROUTING_KEY = 'warren.routing';

/** The Basic authorization header value for a credential. */
function basicAuth(credential: string): string {
  const raw = `${CREDENTIAL_USERNAME}:${credential}`;
  if (typeof btoa === 'function') return `Basic ${btoa(raw)}`;
  return `Basic ${Buffer.from(raw, 'binary').toString('base64')}`;
}

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host === '[::1]'
  );
}

/** Whether a URL addresses this machine (never routed through the ingress). */
function isLoopbackUrl(url: string): boolean {
  try {
    return isLoopbackHost(new URL(url).hostname);
  } catch {
    return false;
  }
}

/**
 * The `chrome.proxy.settings` value that points Chromium at `endpoint`.
 *
 * `all`/`bypass` use `fixed_servers`, the most robust shape; `only` needs a
 * per-site decision `fixed_servers` cannot express, so it compiles to a PAC
 * script naming the ingress as an `HTTPS` proxy. The scheme is always `https`:
 * Chromium accepts `quic` and reads it back as plain `http`, which would send
 * every CONNECT in clear (doc 103 § 2).
 */
export function buildChromiumIngressValue(
  endpoint: IngressEndpoint,
  split: SplitTunnelConfig,
): unknown {
  const { host, port } = endpoint;
  if (split.mode === 'only') {
    return {
      mode: 'pac_script',
      pacScript: { data: buildIngressPac(host, port, split), mandatory: true },
    };
  }
  const bypassList =
    split.mode === 'bypass' ? [...LOOPBACK_BYPASS, ...split.rules] : [...LOOPBACK_BYPASS];
  return {
    mode: 'fixed_servers',
    rules: { singleProxy: { scheme: 'https', host, port }, bypassList },
  };
}

/** A PAC script routing tunnelled hosts to the HTTPS ingress, others direct. */
function buildIngressPac(host: string, port: number, split: SplitTunnelConfig): string {
  const rules = JSON.stringify(split.rules.map((r) => r.toLowerCase()));
  const onlyMode = split.mode === 'only';
  return `function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (host === 'localhost' || dnsDomainIs(host, '.localhost') || host === '127.0.0.1' || host === '::1') return 'DIRECT';
  var rules = ${rules};
  var matched = false;
  for (var i = 0; i < rules.length; i++) {
    var r = rules[i];
    if (r === '*') { matched = true; break; }
    if (r.charAt(0) === '*') r = r.slice(1);
    if (r.charAt(0) === '.') { if (host.slice(-r.length) === r) { matched = true; break; } continue; }
    if (host === r || host.slice(-(r.length + 1)) === '.' + r) { matched = true; break; }
  }
  var tunnel = ${onlyMode ? 'matched' : '!matched'};
  return tunnel ? 'HTTPS ${host}:${port}' : 'DIRECT';
}`;
}

function isLockdownValue(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as {
    mode?: string;
    rules?: { singleProxy?: { scheme?: string; host?: string; port?: number } };
  };
  const proxy = v.rules?.singleProxy;
  return (
    v.mode === 'fixed_servers' &&
    proxy?.scheme === LOCKDOWN_PROXY.scheme &&
    proxy.host === LOCKDOWN_PROXY.host &&
    proxy.port === LOCKDOWN_PROXY.port
  );
}

function chromiumValueOf(record: RoutingState | LockdownState): unknown {
  return record.tier === 'lockdown'
    ? buildChromiumLockdownValue(record.exempt)
    : buildChromiumIngressValue(record.endpoint, record.split);
}

/** Whether the browser can dial this URL's host through a proxy, given SNI
 * needs a real name. IP-literal and non-http URLs are left to the browser. */
function ingressHostFromValue(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const v = value as {
    mode?: string;
    rules?: { singleProxy?: { host?: string } };
    pacScript?: { data?: string };
  };
  if (v.mode === 'fixed_servers') return v.rules?.singleProxy?.host;
  if (v.mode === 'pac_script') {
    const m = v.pacScript?.data?.match(/HTTPS ([^:'"]+):\d+/);
    return m?.[1];
  }
  return undefined;
}

/**
 * Installs Chromium routing and verifies it took control, so a silent no-op
 * (another extension or a policy owns the proxy) surfaces as an error rather
 * than a live UI over an unrouted browser.
 *
 * @throws {WarrenExtensionError} `proxy_uncontrollable` when the settings are
 * owned elsewhere.
 */
export async function installChromiumRouting(
  settings: ProxySettingsLike,
  record: RoutingState | LockdownState,
): Promise<void> {
  const before = await settings.get({});
  if (!controllable(before.levelOfControl)) {
    throw new WarrenExtensionError(
      'proxy_uncontrollable',
      'proxy settings are controlled elsewhere (another extension or enterprise policy)',
    );
  }
  await settings.set({ value: chromiumValueOf(record), scope: 'regular' });
  const after = await settings.get({});
  if (after.levelOfControl !== 'controlled_by_this_extension') {
    throw new WarrenExtensionError(
      'proxy_uncontrollable',
      'the proxy settings did not take (controlled elsewhere)',
    );
  }
}

/** Reads Chromium's live proxy settings: whether this extension controls them,
 * whether the controlling proxy is our ingress at `expectedHost`, and whether
 * it is our lockdown. The browser's own answer, the ground truth a torn-down
 * worker has forgotten. */
export async function readChromiumRouting(
  settings: ProxySettingsLike,
  expectedHost: string,
): Promise<{ controlled: boolean; ours: boolean; lockdown: boolean; host?: string }> {
  const details = await settings.get({});
  const controlled = details.levelOfControl === 'controlled_by_this_extension';
  const lockdown = controlled && isLockdownValue(details.value);
  const host = lockdown ? undefined : ingressHostFromValue(details.value);
  return {
    controlled,
    ours: controlled && host === expectedHost,
    lockdown,
    ...(host ? { host } : {}),
  };
}

/** Restores direct routing. Only an explicit disconnect calls this. */
export async function clearChromiumRouting(settings: ProxySettingsLike): Promise<void> {
  await settings.clear({ scope: 'regular' });
}

function controllable(level: string): boolean {
  return level === 'controllable_by_this_extension' || level === 'controlled_by_this_extension';
}

/** How many answered challenges are remembered to spot a refusal. */
const ANSWERED_MEMORY = 512;

/**
 * Registers the async blocking auth provider that answers a proxy's `407`,
 * with the credential of the proxy that asked: the challenger's host and port
 * decide. A loopback challenger gets the native host's session credentials,
 * and only from the live session owning that listener. Any other challenger
 * gets the browser-proxy credential only when it is the ingress the routing
 * record names. Everything else is cancelled, which stalls the request rather
 * than letting the browser prompt for a password it cannot know.
 *
 * Registered ONCE for the extension's life: it reads both sources fresh on
 * each challenge, so an epoch rollover or a new tunnel needs no
 * re-registration and no routing change.
 */
export function attachChromiumProxyAuth(
  webRequest: WebRequestLike,
  sources: ProxyAuthSources,
): void {
  // A second challenge for a request already answered means the proxy refused
  // the credentials: answering again would loop, so it stalls.
  const answered = new Set<string>();
  async function credentialFor(challenger: {
    host: string;
    port: number;
  }): Promise<ExtensionProxyAuth | undefined> {
    if (isLoopbackHost(challenger.host)) {
      return sources.local?.forListener(`${challenger.host}:${challenger.port}`);
    }
    const ingress = sources.ingress;
    if (!ingress) return undefined;
    const record = await ingress.routing.load();
    if (
      record?.tier !== 'ingress' ||
      record.endpoint.host.toLowerCase() !== challenger.host.toLowerCase() ||
      record.endpoint.port !== challenger.port
    ) {
      return undefined;
    }
    const credential = await ingress.credentials.current();
    return credential === undefined
      ? undefined
      : { username: CREDENTIAL_USERNAME, password: credential };
  }
  async function answer(details: AuthChallenge): Promise<unknown> {
    const { challenger, requestId } = details;
    if (!challenger || requestId === undefined || answered.has(requestId)) {
      return { cancel: true };
    }
    const auth = await credentialFor(challenger);
    if (!auth) return { cancel: true };
    answered.add(requestId);
    if (answered.size > ANSWERED_MEMORY) {
      answered.delete(answered.values().next().value as string);
    }
    return { authCredentials: auth };
  }
  webRequest.onAuthRequired.addListener(
    (details, callback) => {
      // A site's own 401 is not ours to answer: no credential here is for a
      // destination.
      if (!details.isProxy) {
        callback({});
        return;
      }
      answer(details).then(callback, () => callback({ cancel: true }));
    },
    { urls: ['<all_urls>'] },
    ['asyncBlocking'],
  );
}

/**
 * Builds the Firefox ProxyInfo list for `endpoint`. A `masque` endpoint is
 * offered first with the `https` ingress as its failover (same host and port),
 * so an origin without HTTP/3, or a network that drops UDP, still routes through
 * the CONNECT tier. The credential rides on `proxyAuthorizationHeader`, since
 * Firefox forbids `username`/`password` on both `https` and `masque` proxies.
 * With no credential the header is omitted and the ingress challenges.
 *
 * Firefox sends that header on its CONNECT streams only, never on CONNECT-UDP,
 * and it opens a dedicated HTTP/3 connection for CONNECT-UDP (measured against
 * the exit on 2026-09-21), so a header could never admit that connection. The
 * credential therefore also rides in the template's query, which Firefox
 * expands verbatim (RFC 6570) and the ingress reads (`credential=`), inside the
 * same TLS as the header would have been.
 */
export function firefoxProxyInfoFor(
  endpoint: IngressEndpoint,
  credential: string | undefined,
): FirefoxProxyInfo[] {
  const auth = credential === undefined ? {} : { proxyAuthorizationHeader: basicAuth(credential) };
  const httpsLeg: FirefoxProxyInfo = {
    type: 'https',
    host: endpoint.host,
    port: endpoint.port,
    ...auth,
  };
  if (endpoint.kind === 'masque') {
    const masqueTemplate =
      credential === undefined
        ? endpoint.masqueTemplate
        : `${endpoint.masqueTemplate}?credential=${credential}`;
    return [
      {
        type: 'masque',
        host: endpoint.host,
        port: endpoint.port,
        masqueTemplate,
        failoverTimeout: 5,
        ...auth,
      },
      httpsLeg,
    ];
  }
  return [httpsLeg];
}

/**
 * Registers the Firefox `proxy.onRequest` listener. It reloads the persisted
 * {@link RoutingRecord} on every request, so it is correct immediately after a
 * service-worker teardown or a browser restart with no in-memory state, and it
 * decides per request (loopback and bypassed sites go direct, everything else
 * through the ingress or the native host's SOCKS5 listener, or nowhere under a
 * lockdown). If its own store cannot be read it fails closed
 * ({@link FAIL_CLOSED_PROXY}) rather than leaking to a direct route.
 *
 * A multi-hop record is answered with its listener and the session
 * credentials `local` holds for it. Without them (a restart, a dead host) the
 * request fails closed: the listener's port is anyone's to take once its host
 * is gone.
 *
 * Firefox answers `direct` with the browser's own proxy settings when some are
 * set, so `direct` here means "not through the ingress", which leaves a local
 * tunnel installed through `proxy.settings` in charge.
 */
export function attachFirefoxRouting(
  proxy: FirefoxProxyLike,
  store: RoutingStore,
  credentials: CredentialProvider,
  local?: LocalProxyAuth,
): void {
  proxy.onRequest.addListener(
    async (request) => {
      if (isLoopbackUrl(request.url)) return { type: 'direct' };
      let state: RoutingRecord | undefined;
      try {
        state = await store.load();
      } catch {
        // The store is the ground truth; if it cannot be read while a routing
        // may be live, stall rather than expose.
        return FAIL_CLOSED_PROXY;
      }
      if (!state) return { type: 'direct' };
      let host: string;
      try {
        host = new URL(request.url).hostname.toLowerCase();
      } catch {
        return FAIL_CLOSED_PROXY;
      }
      if (state.tier === 'lockdown') {
        return state.exempt.some((h) => h.toLowerCase() === host)
          ? { type: 'direct' }
          : FAIL_CLOSED_PROXY;
      }
      if (!shouldTunnelHost(host, state.split)) return { type: 'direct' };
      if (state.tier === 'multihop') {
        const auth = local?.forListener(state.socks5);
        return auth ? { ...socksProxyInfo(state.socks5), ...auth } : FAIL_CLOSED_PROXY;
      }
      const credential = await credentials.current();
      return firefoxProxyInfoFor(state.endpoint, credential);
    },
    { urls: ['<all_urls>'] },
  );
}

/** The Firefox ProxyInfo for the native host's SOCKS5 endpoint, names resolved
 * at the exit. */
function socksProxyInfo(socks5: string): {
  type: 'socks';
  host: string;
  port: number;
  proxyDNS: true;
} {
  const sep = socks5.lastIndexOf(':');
  return {
    type: 'socks',
    host: socks5.slice(0, sep),
    port: Number(socks5.slice(sep + 1)),
    proxyDNS: true,
  };
}

/** Validates a stored value as a {@link RoutingRecord}; a corrupt store yields
 * `undefined` so the extension never routes on garbage. */
function asRoutingRecord(value: unknown): RoutingRecord | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  if ((value as { tier?: unknown }).tier === 'lockdown') return asLockdownState(value);
  if ((value as { tier?: unknown }).tier === 'multihop') return asMultihopState(value);
  const v = value as Partial<RoutingState>;
  const e = v.endpoint as IngressEndpoint | undefined;
  if (v.tier !== 'ingress' || !e || (e.kind !== 'https' && e.kind !== 'masque')) return undefined;
  if (typeof e.host !== 'string' || typeof e.port !== 'number') return undefined;
  if (e.kind === 'masque' && typeof e.masqueTemplate !== 'string') return undefined;
  if (!v.split || (v.split.mode !== 'all' && v.split.mode !== 'bypass' && v.split.mode !== 'only'))
    return undefined;
  if (!v.exit || typeof v.exit.country !== 'string' || typeof v.exit.city !== 'string')
    return undefined;
  if (v.hops !== 1 && v.hops !== 2) return undefined;
  return v as RoutingState;
}

function isSplit(value: unknown): value is SplitTunnelConfig {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Partial<SplitTunnelConfig>;
  return (
    (v.mode === 'all' || v.mode === 'bypass' || v.mode === 'only') &&
    Array.isArray(v.rules) &&
    v.rules.every((r) => typeof r === 'string')
  );
}

function asMultihopState(value: object): MultihopRoutingState | undefined {
  const v = value as Partial<MultihopRoutingState>;
  if (typeof v.socks5 !== 'string' || !/^[^:]+:\d+$/.test(v.socks5)) return undefined;
  if (!isSplit(v.split) || typeof v.installedAt !== 'number') return undefined;
  return v as MultihopRoutingState;
}

function asLockdownState(value: object): LockdownState | undefined {
  const v = value as Partial<LockdownState>;
  if (!Array.isArray(v.exempt) || !v.exempt.every((h) => typeof h === 'string')) return undefined;
  if (typeof v.installedAt !== 'number') return undefined;
  return v as LockdownState;
}

/** A {@link RoutingStore} over a `chrome.storage`-shaped area. */
export function routingStoreOver(area: RoutingStorageArea): RoutingStore {
  return {
    async load() {
      const got = await area.get(ROUTING_KEY);
      return asRoutingRecord(got[ROUTING_KEY]);
    },
    async save(record) {
      await area.set({ [ROUTING_KEY]: record });
    },
    async clear() {
      await area.remove(ROUTING_KEY);
    },
  };
}

/** An in-memory {@link RoutingStore} for tests. */
export function memoryRoutingStore(): RoutingStore {
  let state: RoutingRecord | undefined;
  return {
    load: async () => state,
    save: async (s) => {
      state = s;
    },
    clear: async () => {
      state = undefined;
    },
  };
}
