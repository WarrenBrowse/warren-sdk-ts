/**
 * `@warrenbrowse/sdk-extension`: browser-scope, non-root Warren VPN for a
 * Chromium or Firefox extension (Manifest V3).
 *
 * The datapath cannot run in the browser; a local native messaging host
 * (`@warrenbrowse/sdk-extension/host`, backed by `@warrenbrowse/sdk-node`)
 * terminates the tunnel and opens local SOCKS5 and HTTP proxy listeners that
 * demand per-session credentials, and this entry routes the whole browser
 * through them with `chrome.proxy` while closing the WebRTC leak. Requires the
 * `proxy`, `privacy` and `nativeMessaging` permissions, plus on Chromium
 * `webRequest`, `webRequestAuthProvider` and a host permission for every URL,
 * so the listener's `407` reaches `attachChromiumProxyAuth`.
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
  type ExtensionProxyAuth,
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
  CREDENTIAL_USERNAME,
  FAIL_CLOSED_PROXY,
  encodeBrowserProxyCredential,
  attachChromiumProxyAuth,
  attachFirefoxRouting,
  buildChromiumIngressValue,
  buildChromiumLockdownValue,
  clearChromiumRouting,
  firefoxProxyInfoFor,
  installChromiumRouting,
  memoryRoutingStore,
  readChromiumRouting,
  routingStoreOver,
  type AuthChallenge,
  type CredentialProvider,
  type FirefoxProxyInfo,
  type FirefoxProxyLike,
  type IngressEndpoint,
  type LocalProxyAuth,
  type LockdownState,
  type MultihopRoutingState,
  type ProxyAuthSources,
  type ProxySettingsLike,
  type RoutingRecord,
  type RoutingState,
  type RoutingStorageArea,
  type RoutingStore,
  type WebRequestLike,
} from './browser-routing.js';
export {
  hardenBrowserLeaks,
  releaseBrowserLeaks,
  type BrowserSettingLike,
  type PrivacyNetworkLike,
} from './leaks.js';
export {
  BROWSER_PROXY_BUNDLE_KEY,
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
