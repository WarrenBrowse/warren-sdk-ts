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

Requires the Rust toolchain and the sibling engine checkouts `../warren-sdk-rs`
AND `../warrenguard` (the Cargo `[patch]` table resolves the engine's crates
from both; see `warren-napi/Cargo.toml`).

```bash
cd warren-napi
# Reuse the engine's target cache to skip recompiling its dependency tree.
CARGO_TARGET_DIR=../../../../../warren-sdk-rs/target pnpm --package=@napi-rs/cli dlx napi build --release
```

This emits `warren-napi.node` next to `index.cjs`. The loader finds it
automatically.

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

## Release / prebuilds (remaining productionization)

Publishing a usable npm package needs a prebuilt `.node` per OS/arch. The intended
flow (standard napi-rs):

1. Pin the engine by git tag in `warren-napi/Cargo.toml` (as the Dart SDK pins
   `warren-sdk`); keep the sibling path for local co-development via a gitignored
   `.cargo/config.toml` override. The authoritative engine rev is tracked in
   `warren-napi/.warrenguard-engine-rev`; `@warrenbrowse/sdk-node`'s
   `prepublishOnly` runs `scripts/assert-engine-protocol.mjs`, which blocks
   `npm publish` unless the engine that compiles into the addon speaks a
   live-fleet wire protocol (its `PROTOCOL_VERSION` is >= v5 in-band client
   auth; a v4 engine cannot connect to the all-v5+ exit fleet).
2. `napi build --release --target <triple>` on each target and publish the
   per-platform packages as `optionalDependencies` (the loader already resolves
   the triple-suffixed binary).

This step needs a cut engine tag and CI access to the private engine repos
(`warren-sdk-rs` + `warrenguard`); it is not wired into the JS CI, which stays
JS-only and green.
