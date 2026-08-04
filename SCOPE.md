# Scope and status

`warren-sdk-ts` is a standalone, clean-room, wire-compatible TypeScript SDK for
the Warren VPN (sibling of `warren-sdk-rs` and `warren-sdk-dart`). The
architecture and decisions live in [`ARCHITECTURE.md`](./ARCHITECTURE.md); the
contributor workflow in [`CONTRIBUTING.md`](./CONTRIBUTING.md). This file is the
current status: what is implemented, what is validated against reality, and what
remains.

## Scope

One npm-published SDK exposing everything a TypeScript developer needs on Warren:
identity and account management, the signed account API, exit discovery and
selection, and the VPN datapath up to the full system-VPN mode, across Node, the
browser and Electron, with no dead weight. The datapath is reused as native code
(never reimplemented in TS); the control plane is pure TS, vector-locked.

## Implemented

- **Control plane** (`@warrenbrowse/sdk-core`, isomorphic): identity (BIP39 ->
  Ed25519, SS58, request signing, mnemonic generation), the signed account API
  with the full `/v1/*` endpoint set + anti-censorship host fallback, discovery
  (signed relay list v10 + multi-hop directory v2 verification) and exit selection.
- **Datapath, Node** (`@warrenbrowse/sdk-node`): proxy mode via the napi-rs engine
  binding (`ProxyTunnel`: exit selection, failover, state events, DAITA, HTTP
  proxy, metrics, NAT-PMP port forwarding, persistent anti-rollback/TOFU via
  `stateDir`) and system-VPN via the `warrend` daemon IPC (`WarrendClient`).
- **Browser** (`@warrenbrowse/sdk-web`): `WarrenWebClient`, the unsigned account
  API plus verification/selection, with no signing key in the page.
- **Facade** (`@warrenbrowse/sdk`): isomorphic control-plane entry.

Every frozen format is replayed from the shared `warren-vectors` (minted by
warren-core): identity, SS58, canonical signing, the signed relay list, and the
multi-hop directory. Cross-implementation compatibility with the source of truth
is proven byte-for-byte, including the multi-hop directory vector that
warren-core's own conformance suite also replays.

## Validated against reality

- **Proxy datapath**: driven from Node through the packaged `ProxyTunnel`, a real
  multi-hop tunnel came up and a SOCKS5 CONNECT egressed at a real production
  exit. Harness: `packages/node/native/validate-egress.mjs`.
- **System-VPN IPC**: the TS `WarrendClient` drove the real privileged `warrend`
  daemon and parsed its real state/error events (network-safe, no reroute).
  Harness: `packages/node/native/validate-warrend.mjs`.
- **Browser is not a VPN**: settled by research + code analysis (see
  ARCHITECTURE.md). The web build is control plane only.

## Quality gates

`pnpm build` + `pnpm lint` + `pnpm typecheck` + `pnpm test` + `pnpm coverage`,
all green. CI runs the same on the org self-hosted runners
(Linux/macOS/Windows) plus a coverage job. The native addon is built locally / at
release, not in CI (the private engine uses sibling path deps a CI checkout cannot
reproduce).

## Remaining (externally gated)

- **Cross-platform prebuilt binaries + a git-tag engine pin** for publishing
  `@warrenbrowse/sdk-node` with its native addon. Blocked on a cut engine tag and
  CI access to the private engine repos (`warren-sdk-rs` + `warrenguard`), whose
  sibling path deps prevent a clean CI/git-dep build. Release steps are documented
  in [`packages/node/native/README.md`](./packages/node/native/README.md).
- **`@warrenbrowse/sdk-extension` real-browser validation**: DONE (2026-07-11).
  The full loop was run inside a real Chromium browser (Brave 149 / Chromium
  150): the example MV3 extension loaded, the native messaging host was
  registered for its assigned id and connected, the wallet was imported into the
  extension vault, `connect()` brought up the multi-hop tunnel and took control
  of `chrome.proxy` (`controlled_by_this_extension`, `fixed_servers` SOCKS5 with
  loopback bypass), a real tab egressed at the NL exit `50.7.46.90` (vs the
  machine's real IP), and `disconnect()` released the proxy. Harness:
  `packages/extension/validate-browser-egress.mjs` (CDP over Node's built-in
  WebSocket). The host protocol + datapath alone are covered by
  `packages/extension/validate-host-egress.mjs`. Note: stable Google Chrome
  137+ removed command-line extension loading, so the browser harness uses a
  Chromium that still honours `--load-extension` (Brave or Chrome for Testing).
