/**
 * `@warrenbrowse/sdk-extension`: browser-scope, non-root Warren VPN for a
 * Chromium extension (Manifest V3).
 *
 * The datapath cannot run in the browser; a local native messaging host
 * (`@warrenbrowse/sdk-extension/host`, backed by `@warrenbrowse/sdk-node`)
 * terminates the tunnel and opens a local SOCKS5 proxy, and this entry routes
 * the whole browser through it with `chrome.proxy` while closing the WebRTC
 * leak. Requires the `proxy`, `privacy` and `nativeMessaging` permissions.
 */
export {
  WarrenBrowserVpn,
  WarrenExtensionError,
  type BrowserVpnConnectOptions,
  type ChromeLike,
  type ChromeSettingLike,
  type ExtensionPlatform,
  type ProxyOnRequestLike,
  type NativePort,
  type WarrenBrowserVpnOptions,
  type WarrenExtensionErrorCode,
} from './client.js';
export {
  DEFAULT_HOST_NAME,
  EXTENSION_PROTOCOL_VERSION,
  parseHostMessage,
  type ExtensionEndpoints,
  type ExtensionExitLocation,
  type ExtensionEntryQuery,
  type ExtensionExitQuery,
  type ExtensionVpnState,
  type HostMessage,
  type HostRequest,
  type HostResponse,
  type HostStateEvent,
} from './protocol.js';
export {
  phaseOfVpnState,
  tunnelStatusOfVpnState,
  type VpnPhaseInputs,
} from './phase.js';
export {
  DEFAULT_SPLIT,
  buildChromiumProxyValue,
  buildFirefoxProxyValue,
  hostMatchesRule,
  shouldTunnelHost,
  type SplitTunnelConfig,
  type SplitTunnelMode,
} from './split.js';
export {
  WarrenKeyring,
  chromeStorageArea,
  type KeyringStorage,
  type KeyringStorageArea,
} from './keyring.js';
export {
  WarrenBrowserProxy,
  type BrowserProxyChrome,
  type BrowserProxyConnectOptions,
  type BrowserProxyEndpoint,
  type BrowserProxyPlatform,
  type BrowserProxySettingsLike,
  type WarrenBrowserProxyOptions,
} from './browser-proxy.js';
export {
  TOKEN_BUNDLE_KEY,
  openTokenStore,
  type TokenStorageArea,
  type TokenStore,
} from './token-store.js';
export {
  connectEdgeTunnel,
  connectEdgeTunnelToExit,
  WarrenEdgeConnection,
  type ConnectEdgeParams,
  type EdgeBidiStream,
  type EdgeCertHash,
  type EdgeReadable,
  type EdgeWritable,
  type WarrenEdgeOptions,
  type WebTransportLike,
} from './edge.js';
