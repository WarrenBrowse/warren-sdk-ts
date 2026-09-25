# sdk-node native datapath (napi-rs)

The in-process proxy datapath for `@warrenbrowse/sdk-node`: a napi-rs addon that
binds the Warren Rust engine (`warren-sdk`) and is consumed through the
`ProxyTunnel` facade in `@warrenbrowse/sdk-node`.

## Layout

- `warren-napi/` the napi-rs crate. `src/lib.rs` exposes `WarrenProxy`
  (`new(mnemonic, apiBase, serverPubkeyPin)`, `connect()`, `shutdown()`,
  `address`). `package.json` holds the `@napi-rs/cli` config (binary name,
  target triples).
- `warren-napi/index.cjs` the platform-aware loader (picks the triple-suffixed
  prebuilt or the local `warren-napi.node`). `index.d.ts` the binding types.
- The TS facade `ProxyTunnel` (`../src/proxy/tunnel.ts`) lazily loads this and is
  the public API; importing the control plane never requires the native addon.

`connect()` verifies the signed relay list and multi-hop directory, cross-checks
the chosen exit, brings up a real multihop tunnel and a local SOCKS5 proxy, and
returns its listen address. This is the non-root proxy mode (no TUN, no
privilege). For the system-VPN mode the SDK drives the privileged `warrend`
daemon instead (`../src/warrend`).

## Build (local)

`warren-napi/Cargo.toml` pins `warren-sdk` to one warren-sdk-rs commit, and its
`[patch]` table resolves the engine's warrenguard and warren-contract crates
from the sibling checkouts `../warrenguard` and `../warren-contract`, which must
sit at the revs that commit names in its `.warrenguard-version` and
`.warren-contract-version`. Cargo fetches the pinned commit itself (the repo is
private, so git needs read access to it).

To build against the working copy `../warren-sdk-rs` instead, add the gitignored
override below; with it, the working copy must sit at the pinned commit for the
build to be the pinned one. Bumping the pin is changing the `rev` in
`warren-napi/Cargo.toml` (and `warren-napi/.warrenguard-engine-rev` to the
warrenguard rev it names).

```bash
cd warren-napi
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[patch."https://github.com/WarrenBrowse/warren-sdk-rs.git"]
warren-sdk = { path = "../../../../../warren-sdk-rs/crates/warren-sdk" }
EOF
# Reuse the engine's target cache to skip recompiling its dependency tree.
CARGO_TARGET_DIR=../../../../../warren-sdk-rs/target pnpm --package=@napi-rs/cli dlx napi build --release --dts index.generated.d.ts
```

This emits `warren-napi.node` next to `index.cjs`. The loader finds it
automatically, but it tries a triple-suffixed `warren-napi.<platform>-<arch>.node`
first, so a stale one left by an earlier `napi build --platform` or a prebuilt
shadows a fresh plain build: build with `--platform` too, or remove it.

`pnpm build` never builds this addon, so a checkout can run one from an older
SDK. The addon reports the shape of its JS surface through `bindingAbi()`
(`BINDING_ABI` in `src/lib.rs`), and the facade refuses anything but its own
`NATIVE_BINDING_ABI` with a `WarrenProxyError` of code `outdated`, an addon
without that export included. Bump both together whenever a field the facade
reads changes. `proxyDatapathStatus()` reads the same verdict without building
a tunnel; the extension's native host reports it at hello.

## Live validation (real exit)

Per the project's TDD rule, the tunnel is validated against a real exit, not just
a fake device. `validate-egress.mjs` uses the packaged `ProxyTunnel` API, brings
up the tunnel, and proves egress with a SOCKS5 CONNECT to `1.1.1.1:443` through
the sealed tunnel (a SYN-ACK back means traffic egresses at the exit). The
mnemonic is read from the environment at runtime and never stored.

```bash
pnpm -C ../.. build           # build @warrenbrowse/sdk-node (dist/)
WARREN_MNEMONIC="<subscribed 12 words>" node validate-egress.mjs
```

Result (production exit, subscribed wallet):

```
client identity : wbBT23UQ...
SOCKS5 proxy up : 127.0.0.1:50534
egress probe 1.1.1.1:443 CONNECT ok (SYN-ACK via the exit, attempt 2)
PASS: TCP egress through the sealed tunnel confirmed (via packaged ProxyTunnel)
```

## Release / prebuilds

The `native-prebuilds` workflow (dispatched by hand) builds the addon for
darwin-arm64, linux-x64 and win32-x64 against the pinned engine: it checks out
warren-sdk-rs at the `rev` in `warren-napi/Cargo.toml`, warrenguard and
warren-contract at the revs that commit names, and publishes each binary to the
rolling `native-prebuilds` release. Installing a prebuilt is dropping it next to
`index.cjs` under its `warren-napi.<platform>-<arch>.node` name.

`@warrenbrowse/sdk-node`'s `prepublishOnly` runs
`scripts/assert-engine-protocol.mjs`, which blocks `npm publish` unless the
engine that compiles into the addon speaks a live-fleet wire protocol (its
`PROTOCOL_VERSION` is >= v5 in-band client auth; a v4 engine cannot connect to
the all-v5+ exit fleet). Publishing the per-platform binaries as npm
`optionalDependencies` (the loader already resolves the triple-suffixed name) is
not wired yet; the JS CI stays JS-only.
