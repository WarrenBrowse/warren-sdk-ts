# Architecture

`warren-sdk-ts` is a standalone TypeScript client SDK for the Warren VPN. It is a
clean-room, wire-compatible reimplementation of the Warren client protocol, a
sibling of `warren-sdk-rs` (the Rust reference) and `warren-sdk-dart`. This is the
canonical architecture doc; for the contributor workflow see
[`CONTRIBUTING.md`](./CONTRIBUTING.md), and for the current status see
[`SCOPE.md`](./SCOPE.md).

## Prime directive: clean-room, wire-compatible

- **Standalone.** Never depends on `warren-core`; `../warren-core` is read-only
  reference material.
- **Wire-compatible byte-for-byte** with the frozen contracts (identity, SS58,
  request signing, signed relay list, multi-hop directory, the `warrend` IPC).
- **Golden vectors are the contract.** Every frozen format is pinned by a file in
  the shared `warren-vectors` repo (a git submodule at `vectors/`), minted by
  warren-core and replayed by every sibling SDK. Never edit a vector to make a
  test pass; fix the code.
- **No-log discipline.** Never put a pubkey, address, IP, nonce or seed in a log
  or error message in clear.

## The split that governs everything: control plane vs datapath

This is inherited from every sibling SDK (`warren-sdk-rs/ARCHITECTURE.md`).

- **Control plane** (low frequency, deterministic, fully pinned by vectors):
  identity (BIP39 -> Ed25519, SS58), request signing, the signed HTTP account
  API, signed-relay-list and multi-hop-directory verification, exit selection.
  This layer is genuinely TypeScript-native: it is just crypto and serialization,
  and it is exactly what the golden vectors freeze.
- **Datapath** (line rate, per-packet crypto, OS privilege): QUIC + RFC 9221
  datagrams, the TLS 1.3 raw-public-key handshake, HPKE multi-hop sealing,
  per-packet AEAD, the smoltcp userspace netstack, the per-OS TUN device and its
  firewall killswitch. This is **never reimplemented in TypeScript**: there is no
  production-grade pure-JS QUIC + TLS-1.3-RPK + userspace TCP/IP stack, and
  per-packet AEAD in a GC'd runtime caps throughput. It is always reused as native
  code from the Rust engine. This is the universal pattern (one native datapath
  core wrapped by thin per-language layers).

## What is possible per environment

A VPN datapath needs raw sockets and OS privilege. The runtimes differ sharply:

| Capability | Browser | Node / CLI | Electron (main) |
|---|:---:|:---:|:---:|
| Identity, signing, account API, discovery, exit selection | yes | yes | yes |
| Datapath: proxy/netstack (local SOCKS5) | no | yes | yes |
| Datapath: system-VPN (TUN, all OS traffic) | no | yes | yes |

- The **browser** build is a control-plane client only and must not hold a
  signing key by default (signing belongs on a backend).
- **Node** is the richest target and the home of a real VPN in TypeScript.
- **Electron**'s main process is Node (full capability set); its renderer is a
  browser (control plane only), talking to the main process over Electron IPC.

### Why a web page cannot be the VPN, even though the protocol is QUIC + TLS 1.3

This was investigated specifically (web research + code analysis of
`warren-sdk-rs/crates/warren-transport`). "Browsers do QUIC via WebTransport, so a
page could dial an exit" does not hold. Three independent, each-sufficient
barriers, the first decisive for Warren:

1. **RFC 7250 raw public keys are unsupported in browsers.** Warren's exit
   handshake is pure TLS 1.3 raw public keys (no X.509): the exit's Ed25519 key
   is pinned in the SNI and verified post-handshake. WebTransport mandates an
   X.509v3 certificate; its only self-signed escape hatch
   (`serverCertificateHashes`) requires an X.509v3 ECDSA P-256 cert with <=14-day
   validity on a non-pooled connection. Chromium's BoringSSL has no raw-public-key
   code path. A TLS-RPK tunnel cannot be terminated in a browser.
2. **No raw QUIC.** A page's only QUIC is a managed WebTransport session
   (HTTP/3 extended CONNECT, session-bound datagrams). It cannot choose ALPN, do a
   bare handshake, or emit Warren's custom QUIC DATAGRAM framing.
3. **No OS-wide capture.** A VPN needs a TUN device plus routing changes; a page
   (and even an extension) has neither, and no raw sockets.

No production VPN (Cloudflare WARP, Tailscale, Mullvad) runs its datapath in a
plain web page; all keep it native. The datapath stays native (`warrend` / the
TUN crate), exactly as the Dart SDK does.

### Browser extension: a real non-root, browser-scope target

An extension does not remove the barriers (no raw sockets, WebTransport still
X.509, no OS capture), so the datapath still cannot run in the browser. But
`chrome.proxy` can route the **whole browser** through a `host:port` proxy and
`nativeMessaging` bridges to a local native binary. So a genuine browser-scope,
non-root VPN reuses our packages: a `@warrenbrowse/sdk-node` native host opens a
local SOCKS5 (no root), and an extension points `chrome.proxy` at it and drives
connect/disconnect over native messaging. Caveats: a native host must still be
installed; scope is the browser only; the extension must close the WebRTC leak
(`webRTCIPHandlingPolicy = disable_non_proxied_udp`) and keep DNS on the tunnel.
This is the `@warrenbrowse/sdk-extension` target (implemented and real-browser
validated 2026-07-11: whole-browser egress at a live NL exit through the native
host, then a clean proxy release on disconnect).

### Not a target: the flagship warren-app

`../warren-app` is a Mullvad fork (Electron + React over gRPC to a `warren-daemon`
that depends directly on warren-core). It does **not** use `warren-sdk-rs`. The
SDK family (Rust, Dart, TS) is the clean-room, vector-locked SDK for everyone
else; warren-app is a parallel first-party line. This SDK is not built to power
today's warren-app.

## Package layout (federated pnpm workspace)

| Package | Runtime | Role | Status |
|---|---|---|---|
| `@warrenbrowse/sdk-core` | isomorphic | Pure-TS control plane: identity, SS58, signing, the signed account API, signed-list + directory verification, exit selection. Zero native deps. | implemented |
| `@warrenbrowse/sdk` | isomorphic facade | App entry. Re-exports the control plane; points at the datapath packages. | implemented |
| `@warrenbrowse/sdk-node` | Node / Electron | Re-exports core + the datapath: `ProxyTunnel` (proxy mode via the napi-rs engine) and `WarrendClient` (system-VPN via the `warrend` daemon IPC). | implemented |
| `@warrenbrowse/sdk-web` | browser | `WarrenWebClient` (unsigned account API) + verification/selection. No signing key in the page. | implemented |
| `@warrenbrowse/sdk-extension` | browser extension | `WarrenBrowserVpn` (MV3; Chromium `chrome.proxy` and Firefox `proxy.settings` dialects, WebRTC + DNS-prefetch leak closure, native messaging) plus the Node native host (`./host`, backed by `sdk-node`). | implemented, real-browser validated (Brave/Chromium, 2026-07-11) |

## Public API surface (as implemented)

### `@warrenbrowse/sdk-core` (and re-exported by `@warrenbrowse/sdk`)

- Identity: `generateMnemonic()`, `seedFromMnemonic(mnemonic)` (full BIP39
  validation, typed `WarrenMnemonicError`), `keyPairFromSeed(seed)` /
  `wipeKeyPair(pair)`, `encodeAddress(pubkey)` / `decodeAddress(address)`
  (SS58 `wb...`, `WARREN_SS58_PREFIX`), `signRequest(...)` /
  `signWithKeyPair(...)`, `signatureHeaders(sig)`, `canonicalMessage(...)`,
  the `HEADER_*` name constants, `randomNonceHex()`.
- Account API: `new WarrenApiClient({ baseUrl, seed?, transport?, alternativeHosts?, now?, nonce? })`
  with `exits`, `register`, `subscription`, `check`, `sessionOpen`, `sessionClose`,
  `deleteAccount`, `submitSupport`, `initApplePayment`, `checkApplePayment`,
  `reportExitDown`, `reportPubkeyMismatch`, `pullPendingVoucher`,
  `multihopDirectory`, plus `dispose()` (zeroizes the signing key). A
  `HttpTransport` seam (`fetchTransport`, default isomorphic `fetch`),
  anti-censorship host fallback advancing only on connect failures, typed
  redacted `WarrenApiError` / `WarrenTransportError`.
- Discovery: `verifySignedRelayList(json, pins?)` (`SIGNED_VERSION`),
  `verifyMultihopDirectory(json, serverPins?, rootPins?)`
  (`MULTIHOP_DIRECTORY_VERSION`), `isExpired`, `isDirectoryExpired`,
  `acceptSignedRelayList` / `acceptMultihopDirectory` (verification + expiry +
  anti-rollback `GenerationStore` + TOFU `ServerKeyStore`, mirroring the Rust
  client flow; in-memory stores provided), `selectExit` / `selectExitWeighted`
  / `selectExitForAttempt`, `relayMatches`; typed `WarrenDiscoveryError` /
  `WarrenDirectoryError` / `NoRelayMatchError`.

### `@warrenbrowse/sdk-node` (re-exports core, adds the datapath)

```ts
import { ProxyTunnel, isProxyDatapathAvailable, WarrendClient } from '@warrenbrowse/sdk-node';

// Proxy mode (non-root): a real tunnel + local SOCKS5/HTTP, via the napi-rs
// engine. Options: alternativeHosts, multihopRootPinHex, daita(Machine),
// requestIpv6, stateDir (anti-rollback + TOFU persistence), onState events.
const tunnel = ProxyTunnel.create({ mnemonic, apiBase, serverPubkeyPin, onState });
const { socks5 } = await tunnel.connect({ selector: { country: 'NL' } });
await tunnel.metrics(); // one-shot datapath counters (supervised: false)
const port = await tunnel.forwardPort('Tcp', 8080, '127.0.0.1:8080'); // NAT-PMP
await tunnel.shutdown();
// Typed WarrenProxyError with stable codes (identity|api|discovery|tunnel|
// config|unsupported|unavailable), redacted at the FFI boundary.

// System-VPN mode: drive the privileged warrend daemon over its JSON IPC.
// Fail-closed lifecycle; typed WarrendError; frame codec exported for tests.
const client = new WarrendClient({ socketPath, onState, onError });
client.open();
client.configure({ mnemonic, apiBase, serverPubkeyPin });
client.connect({ exitPubkeyHex });
```

### `@warrenbrowse/sdk-web`

`WarrenWebClient` exposes only the unsigned account endpoints (`exits`,
`register`, `pullPendingVoucher`, `multihopDirectory`) plus the address codecs and
verification/selection. It never holds a signing key.

## Datapath binding: decided and validated

Three candidates were considered (uniffi->JS, napi-rs, `warrend` IPC). The outcome
is a **hybrid, one mechanism per layer**:

- **Control plane**: pure TS (`@warrenbrowse/sdk-core`), replaying the shared
  golden vectors.
- **Proxy datapath**: **napi-rs**. `packages/node/native/warren-napi` binds the
  full `warren-sdk` engine and is consumed through `ProxyTunnel`. Live-validated:
  a SOCKS5 CONNECT through the tunnel egressed at a real production exit. (uniffi
  was rejected for Node: RN/WASM oriented, and WASM cannot run the datapath.)
- **System-VPN datapath**: the **`warrend` daemon IPC**. `WarrendClient` speaks
  the length-prefixed JSON protocol; validated against the real daemon.

### Native datapath layout

`packages/node/native/warren-napi` is a `@napi-rs/cli` project that builds a
`.node` addon binding `warren-sdk`. A platform-aware `index.cjs` loader picks the
right binary, and the `ProxyTunnel` facade in `@warrenbrowse/sdk-node` loads it
lazily (so importing the control plane never requires the addon;
`isProxyDatapathAvailable()` reports capability). The engine is pinned by git tag
for releases, as the Dart SDK pins `warren-sdk`. The addon is built locally and at
release time, not in CI: the private engine uses sibling path deps to
`warrenguard` that a fresh CI checkout cannot reproduce. See
[`packages/node/native/README.md`](./packages/node/native/README.md).

## Toolchain

pnpm workspace; TypeScript ESM-first with dual ESM+CJS on publish (tsup); the
audited, zero-dependency, isomorphic **noble/scure** crypto stack
(`@noble/hashes`, `@noble/curves`, `@scure/base`, `@scure/bip39`); Biome for
lint+format; Vitest with v8 coverage; Node >= 20, evergreen browsers (ES2022).
Rationale in [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Non-goals

- No pure-TS reimplementation of QUIC, TLS-RPK, HPKE, smoltcp, or the TUN device.
- No VPN datapath in the browser (the web build is control plane only).
- No dependency on warren-core, and no goal of replacing warren-app's daemon.
- No bespoke features beyond what the Rust/Dart SDKs expose. Parity first.
