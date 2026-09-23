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
with `@warrenbrowse/sdk-node` and opening local SOCKS5 and HTTP proxy listeners.
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
  in the connect answer (protocol 2; a version 1 peer is refused at `hello`).
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
  explicit `disconnect()`. If the host dies, the browser keeps pointing at the
  dead proxy: traffic blackholes instead of leaking around the tunnel. The host
  side mirrors this: browser gone (stdin EOF) means the tunnel dies with the
  process. A failed `connect()` leaves the browser as it found it: a routing
  this extension already held (a lockdown, or a tunnel whose host died) is put
  back rather than cleared, and `connect()` over a dead tunnel reconnects in
  place. `applySplit()` changes the rules of a live tunnel without tearing it
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

## Host side (Node, installed once per machine)

The host holds **no identity**: the mnemonic comes from the extension vault at
connect time, and the discovery pin is learned on first use (TOFU), so the host
needs no secrets. It only needs Node reachable by the launcher and, optionally,
a persistent state dir.

```bash
# host.env holds NO mnemonic. Only launcher/runtime knobs.
mkdir -p ~/.warren/state && cat > ~/.warren/host.env <<'EOF'
export WARREN_STATE_DIR="$HOME/.warren/state"   # persist anti-rollback + TOFU pin
# export WARREN_NODE="/path/to/node"            # if node is not on the minimal PATH
# export WARREN_ALLOWED_ORIGINS="<ext-id>"      # pin which extension may drive the host
EOF
chmod 600 ~/.warren/host.env

# register the native messaging manifest for your extension id
node scripts/install-host.mjs --extension-id <your-extension-id>
```

The host entry is `@warrenbrowse/sdk-extension/host`:

```ts
import { configFromEnv, runNativeHost } from '@warrenbrowse/sdk-extension/host';
await runNativeHost(configFromEnv());
```

It requires the `@warrenbrowse/sdk-node` native addon (see
[`packages/node/native`](../node/native)). `WARREN_ALLOWED_ORIGINS`
(comma-separated extension ids / gecko ids) pins which extension may drive the
host: the native-messaging manifest is per-browser, and the browser passes the
caller's origin to the host, the only per-caller gate available.

## Protocol

Version-1 JSON messages over native messaging (Chrome frames them; the host
speaks the 4-byte little-endian stdio framing): `hello` (version handshake, no
identity), `status`, `connect {mnemonic, selector?, entrySelector?, daita?,
httpProxy?}` (`entrySelector` picks the multihop entry country, always a node
distinct from the exit), `disconnect`,
`exits` (the verified relay-list locations, for a location picker), `account
{mnemonic}` (signed subscription lookup, returns `expiresAt`), plus unsolicited
`{type: 'state'}` events. The mnemonic crosses only this local
IPC, never a page or the network. Typed errors: `WarrenExtensionError` with
codes `host_unavailable | protocol | host | already_connected | not_connected |
proxy_uncontrollable | private_browsing_required` (host-reported failures keep
their own code in `hostCode`).

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

# 3. host env (NO mnemonic, NO pin: the wallet is in the extension, the pin is TOFU)
mkdir -p ~/.warren/state && cat > ~/.warren/host.env <<'EOF'
export WARREN_STATE_DIR="$HOME/.warren/state"
# export WARREN_NODE="/path/to/node"   # if node is not on the browser's minimal PATH
EOF
chmod 600 ~/.warren/host.env

# 4. register the native host for that extension id (writes the manifest for
#    Chrome, Chromium, Brave and Edge; add --gecko-id <id@domain> for Firefox)
node scripts/install-host.mjs --extension-id <the-id-from-step-2>

# 5. restart the browser fully, click the extension icon, unlock, Connect.
```

Requirements: the `@warrenbrowse/sdk-node` native addon built locally (see
[`packages/node/native`](../node/native)), and Node resolvable by the launcher
(browsers spawn hosts with a minimal PATH; set `WARREN_NODE=/path/to/node` in
`~/.warren/host.env` if you use nvm or a non-Homebrew install). Debug tip: run
the browser from a terminal to see the host's stderr, and check
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
accepts both keys). Register the host with
`node scripts/install-host.mjs --gecko-id warren-example@warrenbrowse.com`
(Firefox manifests use `allowed_extensions` under the Mozilla paths, and the
host receives the gecko id in argv, matched by `WARREN_ALLOWED_ORIGINS`).

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
