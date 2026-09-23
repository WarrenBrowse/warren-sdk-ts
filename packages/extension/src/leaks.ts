/**
 * The leaks a proxy does not cover, closed for as long as the browser is routed
 * or held by either tier, and handed back to the browser only by an explicit
 * disconnect.
 */

/** A `chrome.types.ChromeSetting`-shaped browser setting. */
export interface BrowserSettingLike {
  set(details: { value: unknown; scope?: string }): unknown;
  clear(details: { scope?: string }): unknown;
}

/** The `privacy.network` settings that leak around a proxy. */
export interface PrivacyNetworkLike {
  webRTCIPHandlingPolicy: BrowserSettingLike;
  /** Absent on browsers that do not expose the DNS prefetcher toggle. */
  networkPredictionEnabled?: BrowserSettingLike;
}

/**
 * Closes both leaks before any traffic follows a proxy: WebRTC gathering
 * candidates over UDP outside the proxy (which hands a page the real public
 * address), and the DNS prefetcher resolving names locally.
 */
export async function hardenBrowserLeaks(network: PrivacyNetworkLike): Promise<void> {
  await network.webRTCIPHandlingPolicy.set({ value: 'disable_non_proxied_udp' });
  await network.networkPredictionEnabled?.set({ value: false });
}

/** Hands both settings back to the browser. */
export async function releaseBrowserLeaks(network: PrivacyNetworkLike): Promise<void> {
  await network.webRTCIPHandlingPolicy.clear({});
  await network.networkPredictionEnabled?.clear({});
}
