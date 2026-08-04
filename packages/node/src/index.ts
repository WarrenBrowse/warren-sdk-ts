/**
 * `@warrenbrowse/sdk-node`: the Node entry for the Warren VPN SDK.
 *
 * Re-exports the isomorphic control plane (`@warrenbrowse/sdk-core`) and adds the
 * Node-only datapath: the in-process proxy mode (`ProxyTunnel`, napi engine
 * binding) and the system-VPN mode (`WarrendClient`, warrend daemon IPC).
 */
export * from '@warrenbrowse/sdk-core';
export * from './warrend/index.js';
export * from './proxy/tunnel.js';
export { defaultTokenStorePath, fileTokenPersistence } from './token-store.js';
