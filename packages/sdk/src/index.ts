/**
 * `@warrenbrowse/sdk`: app-facing facade for the Warren VPN TypeScript SDK.
 *
 * This re-exports the isomorphic control plane (`@warrenbrowse/sdk-core`):
 * identity, the signed account API, signed-relay-list / multi-hop directory
 * verification, and exit selection. It works in Node and the browser.
 *
 * The VPN datapath is platform-specific and lives in dedicated packages, so it is
 * not re-exported here (importing Node-only code would break the browser build):
 *
 * - Node / Electron: `@warrenbrowse/sdk-node` (proxy mode via the napi-rs engine
 *   `ProxyTunnel`, and system-VPN via the `warrend` IPC client).
 * - Browser: `@warrenbrowse/sdk-web` (the unsigned control-plane subset, no
 *   signing key in the page).
 *
 * See SCOPE.md for the full layering.
 */
export * from '@warrenbrowse/sdk-core';
