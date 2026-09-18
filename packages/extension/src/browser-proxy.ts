/**
 * The zero-install browser-proxy tier: route the WHOLE browser through a remote
 * Warren CONNECT ingress, with nothing installed on the machine.
 *
 * This is the other half of warren-core doc 103. Where {@link WarrenBrowserVpn}
 * points the browser at a loopback SOCKS proxy a local native host terminates,
 * this points it at an exit's `:443/tcp` ingress directly, and answers that
 * ingress's authentication challenge with an anonymous browser-proxy credential
 * the background holds.
 *
 * # What it gives, and what it does not
 *
 * It gives a working VPN from a store install alone, which the EdgeConnect
 * WebTransport tier cannot: a Manifest V3 extension cannot hand `chrome.proxy`
 * an in-page transport, so only a real remote proxy routes the whole browser.
 *
 * It is SINGLE HOP. The node terminating the browser's TLS also dials the
 * destination, so one Warren party sees the client address and the destination
 * together, exactly like an ordinary VPN and unlike the multi-hop datapath the
 * native host composes. The credential removes the account half (the node sees
 * an unlinkable token, never a wallet), not the correlation half. Surface it
 * labelled as such.
 *
 * # Per-browser dialect
 *
 * Chromium takes `proxy.settings` with `scheme: 'https'` and answers the
 * ingress's `407` through a blocking `webRequest.onAuthRequired` listener
 * (needs `webRequest` + `webRequestAuthProvider` and host permissions).
 *
 * Firefox refuses `proxy.settings.set` outright without a private-browsing
 * grant the user makes in about:addons, so this tier uses `proxy.onRequest`
 * there, which needs no grant and carries the credential on the ProxyInfo
 * itself, sparing the challenge round trip.
 *
 * `scheme: 'quic'` is deliberately never used: Chromium accepts it and reads it
 * back as `http`, which would send every CONNECT in clear.
 */

import { base64urlnopad } from '@scure/base';
import { WarrenExtensionError } from './client.js';

/**
 * Encodes one pre-minted browser-proxy credential for the wire.
 *
 * The password half of a Basic credential travels through a browser as a
 * string, so the token is base64url-encoded rather than raw; the ingress
 * decodes exactly this. Keeping the encoding here rather than in the product
 * repo keeps one definition of it on both sides of the wire.
 */
export function encodeBrowserProxyCredential(token: Uint8Array): string {
  return base64urlnopad.encode(token);
}

/** Where the CONNECT ingress listens. The host must be a name the browser can
 * validate a certificate for, so it is the node's public cover domain. */
export interface BrowserProxyEndpoint {
  host: string;
  port: number;
}

/** The fixed username the credential rides under; only the password varies. */
const CREDENTIAL_USERNAME = 'warren';

/** Hosts that never go through the ingress. */
const LOOPBACK_BYPASS = ['localhost', '127.0.0.1'];

/** A `chrome.proxy.settings`-shaped surface. */
export interface BrowserProxySettingsLike {
  get?: (details: object) => { levelOfControl: string } | Promise<{ levelOfControl: string }>;
  set: (details: { value: unknown; scope?: string }) => unknown;
  clear: (details?: { scope?: string }) => unknown;
}

/** The subset of the extension API this tier drives. */
export interface BrowserProxyChrome {
  proxy: {
    settings: BrowserProxySettingsLike;
    /** Firefox only; its presence is also the platform auto-detection signal. */
    onRequest?: {
      addListener: (
        listener: (request: { url: string }) => unknown,
        filter: { urls: string[] },
      ) => void;
      removeListener: (listener: (request: { url: string }) => unknown) => void;
    };
  };
  webRequest?: {
    onAuthRequired: {
      addListener: (
        listener: (details: { isProxy: boolean }) => unknown,
        filter: { urls: string[] },
        extra?: string[],
      ) => void;
      removeListener: (listener: (details: { isProxy: boolean }) => unknown) => void;
    };
  };
}

export type BrowserProxyPlatform = 'chromium' | 'firefox';

export interface WarrenBrowserProxyOptions {
  chrome: BrowserProxyChrome;
  /** Auto-detected from `proxy.onRequest` when omitted. */
  platform?: BrowserProxyPlatform;
}

export interface BrowserProxyConnectOptions {
  endpoint: BrowserProxyEndpoint;
  /** The browser-proxy credential, base64url-encoded, spent as the Basic
   * password. */
  credential: string;
}

/**
 * Installs and removes the browser-proxy routing.
 *
 * Fail-closed: the configuration is removed only by {@link disconnect}. A
 * credential that stops verifying leaves the proxy in place and the ingress
 * answers `407`, so the browser stalls rather than falling back to a direct,
 * unprotected route.
 */
export class WarrenBrowserProxy {
  private readonly chrome: BrowserProxyChrome;
  private readonly platformOption: BrowserProxyPlatform | undefined;
  private credential: string | undefined;
  private proxied = false;
  private authListener: ((details: { isProxy: boolean }) => unknown) | undefined;
  private requestListener: ((request: { url: string }) => unknown) | undefined;

  constructor(options: WarrenBrowserProxyOptions) {
    this.chrome = options.chrome;
    this.platformOption = options.platform;
  }

  private get platform(): BrowserProxyPlatform {
    if (this.platformOption) return this.platformOption;
    return this.chrome.proxy.onRequest ? 'firefox' : 'chromium';
  }

  /** Whether the browser is currently routed at the ingress. */
  isProxied(): boolean {
    return this.proxied;
  }

  /**
   * Replaces the credential presented from now on, without touching the proxy
   * configuration. Credentials are epoch-bound, so this runs about hourly and
   * must not interrupt browsing.
   */
  setCredential(credential: string): void {
    this.credential = credential;
  }

  /**
   * Routes the browser through `endpoint`.
   *
   * @throws {WarrenExtensionError} `proxy_uncontrollable` when another
   * extension or a policy owns the proxy settings, so the routing would not
   * take effect, or when the browser surface this tier needs is absent.
   */
  async connect(options: BrowserProxyConnectOptions): Promise<void> {
    this.credential = options.credential;
    if (this.platform === 'firefox') {
      this.installFirefox(options.endpoint);
    } else {
      await this.assertControllable();
      this.installChromium(options.endpoint);
    }
    this.proxied = true;
  }

  /** Removes the routing and the credential provider. */
  async disconnect(): Promise<void> {
    const onRequest = this.chrome.proxy.onRequest;
    if (this.requestListener && onRequest) {
      onRequest.removeListener(this.requestListener);
      this.requestListener = undefined;
    }
    if (this.authListener && this.chrome.webRequest) {
      this.chrome.webRequest.onAuthRequired.removeListener(this.authListener);
      this.authListener = undefined;
    }
    if (this.platform !== 'firefox') {
      await this.chrome.proxy.settings.clear({ scope: 'regular' });
    }
    this.credential = undefined;
    this.proxied = false;
  }

  /** Refuses to install over an owner the browser would not let us displace. */
  private async assertControllable(): Promise<void> {
    const get = this.chrome.proxy.settings.get?.bind(this.chrome.proxy.settings);
    if (!get) return;
    const { levelOfControl } = await get({});
    if (
      levelOfControl !== 'controllable_by_this_extension' &&
      levelOfControl !== 'controlled_by_this_extension'
    ) {
      throw new WarrenExtensionError(
        'proxy_uncontrollable',
        'proxy settings are controlled elsewhere (another extension or enterprise policy)',
      );
    }
  }

  private installChromium(endpoint: BrowserProxyEndpoint): void {
    const webRequest = this.chrome.webRequest;
    if (!webRequest) {
      throw new WarrenExtensionError(
        'proxy_uncontrollable',
        'the browser-proxy tier needs webRequest to answer the ingress authentication challenge',
      );
    }
    // Registered BEFORE the routing: a challenge arriving with no provider
    // makes the browser prompt the user for a proxy password.
    this.authListener = (details) => {
      // Only a proxy challenge, never a site's own 401: the credential is for
      // the ingress and must not be offered to a destination.
      if (!details.isProxy || this.credential === undefined) return {};
      return {
        authCredentials: { username: CREDENTIAL_USERNAME, password: this.credential },
      };
    };
    webRequest.onAuthRequired.addListener(this.authListener, { urls: ['<all_urls>'] }, [
      'blocking',
    ]);
    this.chrome.proxy.settings.set({
      value: {
        mode: 'fixed_servers',
        rules: {
          singleProxy: { scheme: 'https', host: endpoint.host, port: endpoint.port },
          bypassList: [...LOOPBACK_BYPASS],
        },
      },
      scope: 'regular',
    });
  }

  private installFirefox(endpoint: BrowserProxyEndpoint): void {
    const onRequest = this.chrome.proxy.onRequest;
    if (!onRequest) {
      throw new WarrenExtensionError(
        'proxy_uncontrollable',
        'Firefox routing needs proxy.onRequest',
      );
    }
    this.requestListener = (request) => {
      if (isLoopbackUrl(request.url)) return { type: 'direct' };
      if (this.credential === undefined) return { type: 'direct' };
      return {
        type: 'https',
        host: endpoint.host,
        port: endpoint.port,
        proxyAuthorizationHeader: `Basic ${base64(`${CREDENTIAL_USERNAME}:${this.credential}`)}`,
      };
    };
    onRequest.addListener(this.requestListener, { urls: ['<all_urls>'] });
  }
}

/** Whether a URL addresses this machine, which never goes through the ingress. */
function isLoopbackUrl(url: string): boolean {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return (
      host === 'localhost' ||
      host.endsWith('.localhost') ||
      host === '127.0.0.1' ||
      host === '::1' ||
      host === '[::1]'
    );
  } catch {
    return false;
  }
}

/** base64 of an ASCII string, in both a service worker and a page. */
function base64(input: string): string {
  if (typeof btoa === 'function') return btoa(input);
  // Node (tests, the native host): Buffer is the only encoder available.
  return Buffer.from(input, 'binary').toString('base64');
}
