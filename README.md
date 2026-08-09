# warren-sdk-ts

Standalone TypeScript client SDK for the [Warren VPN](https://warren.ro).
Sibling of the reference implementation `warren-sdk-rs` and of `warren-sdk-dart`.

This SDK is a clean-room, wire-compatible reimplementation of the Warren client
protocol. It never depends on `warren-core`; every frozen format is pinned by the
shared golden vectors in `warren-vectors`. See [`ARCHITECTURE.md`](./ARCHITECTURE.md)
for the design (control-plane / datapath split, packages, the binding decision),
[`CONTRIBUTING.md`](./CONTRIBUTING.md) for the workflow, and [`SCOPE.md`](./SCOPE.md)
for current status.

## What runs where

A VPN datapath needs raw sockets and OS privilege, which a browser does not have.
The SDK therefore splits into an isomorphic control plane and a native datapath:

| Capability | Browser | Node / CLI | Electron | Extension + native host |
|---|:---:|:---:|:---:|:---:|
| Identity, signing, account API, exit selection | yes | yes | yes | yes |
| VPN proxy datapath (local SOCKS5) | no | yes | yes | yes (browser-wide, non-root) |
| System-VPN (TUN, all OS traffic) | no | yes | yes | no |

A plain web page cannot be a VPN: there is no raw QUIC, browsers reject Warren's
RFC 7250 raw-public-key TLS, and a page cannot capture OS traffic. See
[`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full reasoning.

## Packages

| Package | Status | Role |
|---|---|---|
| [`@warrenbrowse/sdk-core`](./packages/core) | implemented | Pure-TS control plane: identity, SS58, request signing, signed account API, signed-relay-list verification, exit selection. Isomorphic, zero native deps. |
| [`@warrenbrowse/sdk`](./packages/sdk) | implemented (facade) | App-facing entry. Re-exports the control plane; wires the datapath as the native packages land. |
| [`@warrenbrowse/sdk-node`](./packages/node) | implemented | Node datapath: `warrend` system-VPN IPC client + the napi-rs proxy-mode binding (live-validated against a real exit; see [`native/`](./packages/node/native)). Re-exports the control plane. |
| [`@warrenbrowse/sdk-web`](./packages/web) | implemented | Browser control-plane entry: `WarrenWebClient` (unsigned account API) + verification/selection. No signing key in the page by default. |
| [`@warrenbrowse/sdk-extension`](./packages/extension) | implemented | Browser-scope non-root VPN for MV3 extensions: `chrome.proxy` + WebRTC-leak closure + native messaging to a local `sdk-node` host. Real-browser validation pending. |

## Quickstart

**Control plane** (isomorphic, `@warrenbrowse/sdk`): identity, account API, discovery.

```ts
import {
  generateMnemonic,
  seedFromMnemonic,
  keyPairFromSeed,
  encodeAddress,
  WarrenApiClient,
  verifySignedRelayList,
  selectExitWeighted,
} from '@warrenbrowse/sdk';

const seed = seedFromMnemonic(process.env.WARREN_MNEMONIC!); // generateMnemonic() for a fresh one
const address = encodeAddress(keyPairFromSeed(seed).publicKey); // wb...

const api = new WarrenApiClient({ baseUrl: 'https://api.warrenbrowse.com', seed });
const sub = await api.subscription();

const SERVER_PUBKEY_HEX = '...'; // pinned discovery server key
const verified = verifySignedRelayList(await api.exits(), [SERVER_PUBKEY_HEX]);
const exit = selectExitWeighted(verified.relays, { location: { kind: 'country', country: 'NL' } });
```

**VPN datapath, Node** (`@warrenbrowse/sdk-node`): the non-root proxy mode brings up a
real tunnel and a local SOCKS5 proxy via the native engine.

```ts
import { ProxyTunnel } from '@warrenbrowse/sdk-node';

const tunnel = ProxyTunnel.create({
  mnemonic: process.env.WARREN_MNEMONIC!,
  apiBase: 'https://api.warrenbrowse.com',
  serverPubkeyPin: SERVER_PUBKEY_HEX,
  onState: (state) => console.log('tunnel', state), // connecting/connected/reconnecting/...
});
const { socks5 } = await tunnel.connect({ selector: { country: 'NL' } });
// e.g. 127.0.0.1:1080; point your client here. Also available: httpProxy,
// failover exits, DAITA, metrics(), forwardPort() (NAT-PMP).
await tunnel.shutdown();
```

For the system-VPN mode (captures all OS traffic), `@warrenbrowse/sdk-node` also
exposes `WarrendClient`, which drives the privileged `warrend` daemon.

**Browser** (`@warrenbrowse/sdk-web`): control plane only, no signing key in the page.

```ts
import { WarrenWebClient } from '@warrenbrowse/sdk-web';

const client = new WarrenWebClient({ baseUrl: 'https://api.warrenbrowse.com' });
const { expires_at } = await client.register({ pubkey_ss58: address, voucher_secret });
```

## Example app

[`examples/vpn-desk`](./examples/vpn-desk) is a complete local VPN dashboard
(Node backend holding the identity + a modern localhost web UI) demonstrating
the recommended integration patterns: seed isolation, `accept*` stores, typed
error handling, state events and fail-closed shutdown.

```bash
WARREN_MNEMONIC="..." pnpm --filter warren-example-vpn-desk start
# open http://127.0.0.1:8642
```

The browser-extension example (MV3 popup + native host) lives in
[`packages/extension/example`](./packages/extension/example).

## Development

Requirements: Node >= 20, pnpm.

```bash
git submodule update --init   # the warren-vectors golden vectors (private)
pnpm install
pnpm build            # tsup, dual ESM + CJS + .d.ts per package (build first)
pnpm lint             # biome
pnpm typecheck        # tsc --noEmit per package
pnpm test             # vitest, replays the golden vectors
pnpm coverage         # vitest v8 coverage with thresholds
```

### Release channel (build-time)

`WARREN_PRODUCT_ENV` picks the channel a build targets, `prod` (the default when
unset) or `beta`, and `apiBaseUrl` from `@warrenbrowse/sdk-core` resolves to that
channel's API base (`https://api.warrenbrowse.com` or
`https://api.beta.warrenbrowse.com`). Any other value fails the build, and an
explicit `baseUrl`/`apiBase` passed by the caller still wins.

```bash
pnpm build                              # prod
WARREN_PRODUCT_ENV=beta pnpm build      # beta
```

CI runs this on the org self-hosted runners (Linux/macOS/Windows) plus a coverage
job; see `.github/workflows/ci.yml`. The native proxy addon
(`packages/node/native`) is built locally and at release time, not in CI, because
the private engine uses sibling path deps a CI checkout cannot reproduce.

The golden vectors live in `vectors/` as a git submodule of `warren-vectors`,
shared with every sibling SDK. Never edit a vector to make a test pass; fix the
code. A vector change is a wire-format break.

The `warren-vectors` submodule is currently private, so outside contributors
cannot fetch it and `pnpm test` cannot replay the golden vectors from a public
clone. The org CI replays them on every push.

Full workflow (TDD, native addon build, live validations, conventions): see
[`CONTRIBUTING.md`](./CONTRIBUTING.md).

## License

AGPL-3.0-or-later. The full text is in [LICENSE](./LICENSE).
