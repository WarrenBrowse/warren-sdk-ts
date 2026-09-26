# @warrenbrowse/sdk-extension

Browser-scope, non-root [Warren VPN](https://warrenbrowse.com) for Chromium
extensions (Manifest V3).

A web page or extension cannot run the native TUN datapath (no raw QUIC, no TLS
raw public keys, no TUN) for whole-browser or whole-OS traffic. The partial
exception is the EdgeConnect tier (below): a WebTransport session can carry
CODE-INITIATED traffic straight to an exit at a lower protection tier, but it
cannot proxy the whole browser. For the whole-browser VPN this package is built
around, the split is: the **extension is the wallet** (the Warren account lives
here, encrypted, exactly as MetaMask/Phantom keep a key), and a **local native
messaging host** runs only the datapath, terminating the real multi-hop tunnel
and opening local SOCKS5 and HTTP proxy listeners. The host users install is
the **Warren helper** (`warren-host`), one self-contained binary that links the
Rust engine directly (see [The helper](#the-helper-warren-host)); the Node host
in `src/host` speaks the same protocol over `@warrenbrowse/sdk-node`.
The extension routes the **whole browser** through them with `chrome.proxy` and
closes the WebRTC leak. Scope is the browser only; for all-OS traffic use the system-VPN
mode of `@warrenbrowse/sdk-node`.

## The wallet ({@link WarrenKeyring})

The account mnemonic is created or imported in the extension and stored as an
**encrypted vault** ({@link WarrenVault} in `@warrenbrowse/sdk-core`):
PBKDF2-HMAC-SHA256 at 900k iterations derives an AES-256-GCM key from the user's
password. The vault blob lives in `chrome.storage.local`; the mnemonic is only
ever decrypted into memory on unlock. The derived key is cached in
`chrome.storage.session` (in-memory, `TRUSTED_CONTEXTS`, wiped on browser close)
so the keyring rehydrates after the MV3 service worker is killed without
re-prompting; the cache dies with the session, forcing a password unlock next
launch. Auto-lock and explicit lock wipe both.

## Security model

- **The wallet stays in the extension.** The mnemonic is never sent to a page or
  over the network. At connect time it is handed once to the **local** native
  host over native messaging (a user-installed datapath, like a local signer),
  used, and not persisted there; the host is otherwise identity-less.
- **The listeners demand credentials.** Every account and process on the
  machine can reach a loopback port, so the host's listeners refuse any client
  without the credentials it mints for each tunnel, and hands them over once,
  in the connect answer.
  `WarrenBrowserVpn` keeps them in memory for as long as that host lives and
  gives them out through `forListener(address)` only for its own listeners.
  Chromium cannot authenticate to a SOCKS5 proxy, so it is pointed at the HTTP
  listener, and `attachChromiumProxyAuth(chrome.webRequest, { local: vpn })`
  answers the listener's `407`; a browser-proxy tier passes its ingress source
  too, and the challenger's host and port decide which credential answers, so
  neither ever reaches the other's proxy. Firefox is routed per request by a
  `proxy.onRequest` handler whose SOCKS5 answers carry them. On Chromium this
  needs the `webRequest` and `webRequestAuthProvider` permissions and a host
  permission for every URL.
- **The extension picks the API.** Its first message on every port is a
  `hello` naming its release channel (`WarrenBrowserVpnOptions.channel`), and
  the host reaches that channel's API whatever channel its own build defaults
  to; only an explicit `WARREN_API_BASE` in the host's environment overrides
  it. A host speaking an older protocol (version 3 today) is refused at that
  `hello`, before it is asked anything, and the port is closed so the next
  attempt spawns the host an update put in place.
- **Proxy control is verified, not assumed.** In Chromium the most recently
  installed extension wins the proxy setting and a losing `set()` is a silent
  no-op. `connect()` checks `levelOfControl` before dialing the tunnel and
  re-verifies after applying the proxy; either failure throws a typed
  `proxy_uncontrollable` error (also raised on enterprise-managed browsers)
  and rolls the leak hardening back.
- **Leak hardening beyond WebRTC.** The DNS prefetcher resolves names locally
  even under SOCKS5, so `networkPredictionEnabled` is switched off together
  with `webRTCIPHandlingPolicy = disable_non_proxied_udp`, both before the
  proxy is applied and both restored on explicit disconnect. DNS stays on the
  tunnel: both browsers hand hostnames to the proxy, which resolves at the exit.
- **Fail-closed.** Once connected, the proxy settings are only removed by an
  explicit `disconnect()`. If the host dies, the port it released is anyone's
  to bind, so the browser never stays pointed at it: Chromium moves onto the
  lockdown block (a loopback proxy nothing answers), Firefox's per-request
  handler refuses the dead listener, and `onHostLost()` listeners hear it so
  the product can record its hold. Traffic stalls instead of leaking. The host
  side mirrors this: browser gone (stdin EOF) means the tunnel dies with the
  process. A failed `connect()` leaves the browser as it found it: a routing
  this extension already held (a lockdown, or the block a dead host left) is
  put back rather than cleared, and `connect()` over a dead tunnel reconnects
  in place. `applySplit()` changes the rules of a live tunnel without tearing it
  down, so a rule edit never opens a direct window.
- **Lockdown.** A `LockdownState` saved to the routing store and installed with
  `installChromiumRouting` (or answered by `attachFirefoxRouting`) holds the
  browser blocked while its user wants protection and no tier carries it: every
  request stalls except loopback and the exempt hosts, which should be exactly
  what reconnecting needs (the Warren API). Keep the store in
  `chrome.storage.local` so the hold survives a browser restart and an update.
- **Supply chain is the real risk** (per the 2025 wallet-extension breaches):
  the vault crypto is table stakes; protect the release pipeline (hardware-backed
  store keys, pinned/audited deps, signed commits, mandatory pre-publish review,
  strict CSP with no `unsafe-eval`).
- **What the multi-hop does and does not hide.** The sealed multi-hop guarantees
  that no *single* Warren node sees both the user's IP and their destination
  (the entry sees the IP but only opaque forwarded ciphertext; the exit sees the
  destination but not the IP; entry != exit is enforced). It does **not** defend
  against a *global passive adversary* who observes multiple links and correlates
  by timing/volume, the classic Tor limitation. DAITA (the `daita` connect
  option) is the partial mitigation for that timing channel. Describe the
  guarantee in these terms; do not claim unconditional unlinkability.

## Extension side (bundle into your MV3 service worker)

```ts
import {
  WarrenBrowserVpn,
  WarrenKeyring,
  attachChromiumProxyAuth,
  chromeStorageArea,
} from '@warrenbrowse/sdk-extension';

const keyring = new WarrenKeyring({
  local: chromeStorageArea(chrome.storage.local),
  session: chromeStorageArea(chrome.storage.session),
});
// onboarding: await keyring.create(password) or keyring.import(mnemonic, password)
// on each wake: await keyring.rehydrate(); popup unlock: await keyring.unlock(password)

const vpn = new WarrenBrowserVpn({ onState: (s) => console.log('vpn', s) });
// Chromium: answers the host listener's 407 with the session credentials.
// Register it at the top level of the service worker, on every start.
attachChromiumProxyAuth(chrome.webRequest, { local: vpn });
const mnemonic = await keyring.getMnemonic(); // from the unlocked vault
await vpn.connect({ mnemonic, selector: { country: 'NL' } });
// the whole browser now egresses at the Warren exit
await vpn.disconnect();
```

### Split tunneling (per-site)

`connect({ split })` chooses which sites follow the tunnel. `rules` are host
patterns: a bare domain (`example.com`) matches it and its subdomains,
`*.example.com` matches subdomains only, `*` matches everything; loopback is
always direct.

```ts
// everything except your bank goes through Warren
await vpn.connect({ mnemonic, split: { mode: 'bypass', rules: ['bank.example'] } });
// only work sites go through Warren, the rest stay direct
await vpn.connect({ mnemonic, split: { mode: 'only', rules: ['*.corp.example'] } });
```

Under the hood the same matcher drives both platforms: Chromium uses the
native `bypassList` for `bypass` and a generated PAC script for `only`;
Firefox uses `passthrough` for `bypass` and a `proxy.onRequest` handler for
`only`. The decision is identical across browsers.

Manifest permissions: `"proxy"`, `"privacy"`, `"nativeMessaging"`. Harden the
manifest like the example does: an explicit
`content_security_policy.extension_pages` of
`script-src 'self'; object-src 'self';` and
`"externally_connectable": {"ids": []}` (without it, every installed extension
may message yours), and validate `sender.id === chrome.runtime.id` in message
listeners.

Service worker lifecycle: an open `connectNative` port keeps the MV3 worker
alive (Chrome 105+), but assume it can still die. The host owns the tunnel
state: re-query with `vpn.status()` on wake instead of trusting worker memory,
treat the persisted proxy setting as ground truth, keep UI state in
`chrome.storage.session`, and reconnect from the port's `onDisconnect` with
backoff when you need an always-on session. See [`example/`](./example) for a
complete minimal extension.

## The helper (`warren-host`)

The shipped native messaging host is `warren-host`, the crate in
[`native-host/`](./native-host): one binary with the engine (`warren-sdk`)
linked in, so it needs no Node, no clone and no build on the user's machine. It
speaks protocol version 3 exactly like the Node host below, always answers
`hello` with `datapath: "ready"`, and installs itself per user without
administrator rights.

### Installing it

Every route runs the same `warren-host install`, which copies the binary to the
per-user location and registers `com.warrenbrowse.host` with every browser
profile it finds (Chrome, Chromium, Brave, Edge, Vivaldi, Opera, Arc on macOS,
Firefox, LibreWolf; all of them when none is found yet):

```bash
# macOS and Linux
curl -fsSL https://github.com/WarrenBrowse/warren-sdk-ts/releases/download/<TAG>/install.sh | sh
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/WarrenBrowse/warren-sdk-ts/releases/download/<TAG>/install.ps1 | iex"
```

Or download from the release and open it: `Warren-Helper-Setup.exe` on Windows
(a double-click installs it and waits for Enter), `Warren-Helper.pkg` on macOS
(unsigned for now, so Gatekeeper wants a right click, Open; its postinstall
runs `warren-host install` as the logged-in user). `<TAG>` is the release tag,
for example `host-beta-v0.1.0`. Both scripts refuse a binary whose SHA256 does
not match the release's `SHA256SUMS`.

| | macOS | Linux | Windows |
|---|---|---|---|
| binary | `~/Library/Application Support/Warren/Helper/warren-host` | `${XDG_DATA_HOME:-~/.local/share}/warren/helper/warren-host` | `%LOCALAPPDATA%\Warren\Helper\warren-host.exe` |
| manifests | each browser's `NativeMessagingHosts` directory | same | two JSON files next to the binary, named by `HKCU\Software\<vendor>\NativeMessagingHosts\com.warrenbrowse.host` |

`warren-host uninstall` removes the binary, every manifest and registry key,
and its state; `warren-host status` lists where it is registered;
`warren-host --version` prints the version and the build's channel.

### Who may call it

Browsers pass the caller to the host: Chromium its origin
(`chrome-extension://<id>/`), Firefox the manifest path and the add-on id. The
helper serves only the extension ids baked for its build's channel (beta:
`dgkleicjbkfinjhhhmalipaepnlchfib` and `vpn-beta@warrenbrowse.com`; prod:
`icngiamijikflhcilcgfpeipelhomldk` and `vpn@warrenbrowse.com`) plus the ids
recorded at install time for development builds:

```bash
warren-host install --extension-id <chromium id> --gecko-id <id@domain>
```

The API it reaches is the one of the channel the extension names at `hello`;
a `hello` without a channel gets the build's own (`WARREN_PRODUCT_ENV` at
compile time, prod by default). It pins the server key and the multihop
directory's offline root from the engine's product anchors, and keeps the
anti-rollback floors per channel under the helper's `state/` directory. The mnemonic arrives in a `connect` or
`account` request, is used and wiped, and is never stored or logged.

### Building the helper

`native-host/Cargo.toml` pins `warren-sdk` to the same warren-sdk-rs commit as
the napi addon, and its `[patch]` table resolves the engine crates from the
sibling checkouts `../warrenguard` and `../warren-contract`, which must sit at
the revs that commit names. To build from local checkouts, add the gitignored
override (the one CI writes in `.github/actions/engine-siblings`):

```bash
cd native-host
mkdir -p .cargo
printf '%s\n' '[patch."https://github.com/WarrenBrowse/warren-sdk-rs.git"]' \
  'warren-sdk = { path = "../../../../warren-sdk-rs/crates/warren-sdk" }' > .cargo/config.toml
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
WARREN_PRODUCT_ENV=beta cargo build --release
node validate-egress.mjs target/release/warren-host   # WARREN_MNEMONIC=... adds the live tunnel part
```

`cargo test` drives the session against a fake tunnel, the stdio loop over
in-memory pipes, the built binary over real framing, and `install` /
`uninstall` into a temporary home directory. `validate-egress.mjs` launches the
binary as Chromium does and runs `hello` and `exits`, then, with
`WARREN_MNEMONIC` set, `account`, `connect` and `status` (both must name the
same exit), an authenticated SOCKS5 CONNECT through the tunnel, `disconnect`,
and a connect through an entry in another country whose answer must still name
the exit's country.

### Releases

`.github/workflows/release-host.yml` publishes one channel per tag:
`host-beta-vX.Y.Z` a beta prerelease, `host-vX.Y.Z` a prod release. The version
must equal the crate's and be the highest of its own series, and the commit
must be on `main` with a green CI run. Assets: `warren-host-macos-universal`,
`Warren-Helper.pkg`, `warren-host-linux-x86_64` and `warren-host-linux-aarch64`
(static musl), `Warren-Helper-Setup.exe`, `install.sh`, `install.ps1` and
`SHA256SUMS`. `workflow_dispatch` is a dry run that builds every lane.

## Node host (`@warrenbrowse/sdk-extension/host`)

The same protocol served from Node over `@warrenbrowse/sdk-node`, for SDK
consumers that run the host in their own Node process. The extension product
installs the helper above instead. The Node host needs the
`@warrenbrowse/sdk-node` native addon (see
[`packages/node/native`](../node/native)) and reports its state at `hello`
(`missing` or `outdated` when the addon is absent or from another SDK).

```ts
import { configFromEnv, runNativeHost } from '@warrenbrowse/sdk-extension/host';
await runNativeHost(configFromEnv());
```

For development, `node scripts/install-host.mjs --extension-id <id>` registers
the Node launcher (`scripts/warren-host-launcher.sh`, which reads
`~/.warren/host.env`). `WARREN_ALLOWED_ORIGINS` (comma-separated extension ids
or gecko ids) pins which extension may drive it, and `WARREN_STATE_DIR`
persists its anti-rollback floors.

`validate-host-egress.mjs` drives the Node host over real native-messaging
framing: `hello`, `exits`, `account`, `connect` and `status` (both must name the
same exit country, which it prints), an authenticated SOCKS5 CONNECT through the
tunnel, then `disconnect`. It reaches the build's channel API unless
`WARREN_API_BASE` names another, so point it at whichever channel is live:

```bash
WARREN_API_BASE=https://api.beta.warrenbrowse.com \
  WARREN_MNEMONIC="<subscribed 12 words>" node validate-host-egress.mjs
```

## Protocol

Version-3 JSON messages over native messaging (Chrome frames them; the host
speaks the 4-byte little-endian stdio framing): `hello {protocol, channel?}`
(version handshake naming the extension's channel, no identity; the answer
carries `datapath`), `status` (the state, and while a tunnel is up its
`endpoints` and `exit`), `connect {mnemonic, selector?, entrySelector?, daita?,
httpProxy?}` (`entrySelector` picks the multihop entry country, always a node
distinct from the exit; the answer carries the listener credentials and
`exit`), `disconnect`, `exits` (the verified relay-list locations, for a location
picker), `account {mnemonic}` (signed subscription lookup, returns
`expiresAt`), plus unsolicited `{type: 'state'}` events. The mnemonic crosses
only this local IPC, never a page or the network. Typed errors:
`WarrenExtensionError` with codes `host_unavailable | protocol | host |
already_connected | not_connected | proxy_uncontrollable |
private_browsing_required` (host-reported failures keep their own code in
`hostCode`).

`exit` is `{country, city}`: the ISO 3166-1 alpha-2 country (upper-case) and the
city of the exit the tunnel lands on, as the verified relay list names them.
With an entry selector it is still the exit, never the entry. The field is
additive within version 3: an older extension ignores it, and
`WarrenBrowserVpn.exitLocation()` returns `undefined` when a host does not name
it (an older host, or the Node host on an addon built before the exit crossed
the napi boundary), with no live tunnel, and once the host is gone. `status()`
relays it as well.

## EdgeConnect (browser WebTransport tier)

`connectEdgeTunnel` / `connectEdgeTunnelToExit` are a second, narrower tier: a
WebTransport-over-HTTP/3 session opened straight from in-page or extension JS
to a Warren edge, carrying only CODE-INITIATED traffic (it cannot proxy the
whole browser, unlike `WarrenBrowserVpn` above). It is a LOWER protection tier
than the native host datapath: a Warren session nested inside
TLS-over-HTTP/3 is the nested-TLS shape the native path avoids. `connectEdgeTunnelToExit`
is zero-config: it derives the WebTransport URL from a `VerifiedExit`'s host
plus the well-known `WARREN_EDGE_PORT` (8443) and pins the ephemeral cert from
the signed directory's `edgeCertSha256`. It does not replace the native tunnel
described above; reach for it only where native messaging is genuinely
unavailable.

## Trying the example extension (Chrome / Brave / Edge / Chromium / Firefox)

From this package directory:

```bash
# 1. bundle the client into the example extension
pnpm build && pnpm build:example

# 2. load it: brave://extensions (or chrome://extensions), enable Developer
#    mode, "Load unpacked" -> select packages/extension/example.
#    Copy the extension ID it gets assigned. A full-tab onboarding opens on
#    first load: create or import your Warren wallet (this sets the password
#    that encrypts the vault). No CLI, no mnemonic on disk.

# 3. install the helper and let it serve this extension id too (the helper
#    only serves the product's own ids otherwise). From a release, or from a
#    local build (see "Building the helper"):
curl -fsSL https://github.com/WarrenBrowse/warren-sdk-ts/releases/download/<TAG>/install.sh \
  | sh -s -- --extension-id <the-id-from-step-2>

# 4. nothing to configure: no mnemonic, no pin, no Node on the browser's PATH.

# 5. restart the browser fully, click the extension icon, unlock, Connect.
```

The Node host still works for this walkthrough (`node scripts/install-host.mjs
--extension-id <id>` with the native addon built, see "Node host" above).
Debug tip: run the browser from a terminal to see the host's stderr, and check
`brave://extensions` -> the extension's "Errors" panel for
`Specified native messaging host not found` (manifest not seen: wrong
directory or the browser was not fully restarted).

## Firefox

Supported by the same `WarrenBrowserVpn` class: the proxy-settings dialect is
auto-detected (or forced with `platform: 'firefox'`). Differences handled for
you: a `proxy.onRequest` handler whose SOCKS5 answers carry the listener's
credentials (Firefox accepts `username` and `password` on a `socks` ProxyInfo
only), a `browser.proxy.settings` manual-socks shape with an explicit
`proxyDNS: true` (default only since Firefox 128) holding the browser on the
listener should that handler be gone, a typed
`private_browsing_required` error when the user has not granted
private-browsing access (Firefox refuses proxy control without it; guide the
user to enable it in the add-on's settings), and a `false` set() result mapped
to `proxy_uncontrollable`. The example manifest carries the required
`browser_specific_settings.gecko` keys (id, `strict_min_version`, AMO
`data_collection_permissions`) and declares `background.scripts` alongside
`service_worker` (Firefox runs an event page, not a worker; Firefox 121+
accepts both keys). Let the helper serve the example with
`warren-host install --gecko-id warren-example@warrenbrowse.com` (Firefox
manifests use `allowed_extensions` under the Mozilla paths, and the host
receives the gecko id in argv, matched against the ids the helper trusts).

## Validation

Real-browser validation is DONE (2026-07-11). The full loop ran in a live
Chromium browser (Brave 149 / Chromium 150): the example extension loaded, the
native host registered and connected, the vault-held wallet drove `connect()`,
`chrome.proxy` came under the extension's control (`fixed_servers` SOCKS5, loopback
bypassed), a real tab egressed at the NL exit `50.7.46.90` (not the machine's IP),
and `disconnect()` released the proxy. The reusable harness is
[`validate-browser-egress.mjs`](./validate-browser-egress.mjs) (drives a real
browser over CDP); [`validate-host-egress.mjs`](./validate-host-egress.mjs) covers
the native-host protocol + multi-hop datapath on their own. Revalidated on
2026-09-23 once the listeners demanded credentials, with the product extension
and a real host at a beta exit: Chrome for Testing through the HTTP listener
(`http://` and `https://` both egressed at the exit, the `407` answered by
`attachChromiumProxyAuth`), Firefox 155 through the SOCKS5 listener with the
credentials on its `proxy.onRequest` answers. Stable Google Chrome
137+ ignores `--load-extension`, so the browser harness targets a Chromium that
still honours it (Brave or Chrome for Testing); the shipped extension itself works
unchanged on stock Chrome once installed normally.

## Not yet covered

- Chrome Web Store / AMO submission (per-permission justifications, privacy
  policy and prominent traffic-handling disclosure required for a VPN
  listing; no remote code, which this package already satisfies).

## License

AGPL-3.0-or-later.
