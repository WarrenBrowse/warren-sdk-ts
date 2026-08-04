# vpn-desk

A local desktop-style VPN dashboard built on `@warrenbrowse/sdk-node`.

A plain Node process (the trusted side) holds the mnemonic, runs the SDK
datapath, and serves a small web UI on `127.0.0.1:8642`. The page is pure UI
over a localhost JSON API: the seed never reaches the browser. No frameworks,
no external dependencies.

## Run

From the repo root:

```sh
pnpm install
pnpm build                       # builds the workspace packages

# Optional but recommended: build the native datapath addon so the connect
# button works. Without it the app starts in control-plane only mode
# (exits and account info, no tunnel).
cd packages/node/native/warren-napi && npm run build && cd -

WARREN_MNEMONIC="your twelve word bip39 mnemonic ..." \
  pnpm --filter warren-example-vpn-desk start
```

Then open http://127.0.0.1:8642.

Environment:

- `WARREN_MNEMONIC` (required): BIP39 mnemonic of a subscribed account. Passed
  via env so it never lands in shell history files or argv listings.
- `WARREN_API_BASE` (default: the API base of the SDK build's release channel).
- `WARREN_SERVER_PUBKEY_PIN` (optional): explicit discovery server pubkey pin,
  64-char hex. When unset the app relies on trust-on-first-use: the first
  verified relay list's signer key is pinned in memory for the rest of the run.

## Best practices demonstrated

- **Seed isolation**: the mnemonic and seed live only in the Node process; the
  browser talks to a loopback-bound JSON API and never sees identity material.
- **Verified discovery**: exits come from `acceptSignedRelayList`, which
  enforces the signature, expiry, anti-rollback and TOFU pinning. The example
  uses the in-memory stores; a real app supplies persistent
  `GenerationStore` / `ServerKeyStore` implementations so anti-rollback and the
  TOFU pin survive restarts.
- **Typed error handling**: `WarrenProxyError` / `WarrenApiError` /
  `WarrenDiscoveryError` codes are mapped to clean JSON error responses; raw
  causes and server bodies never reach the page.
- **Fail-closed shutdown**: SIGINT/SIGTERM (and any failed connect) tear the
  tunnel down via `ProxyTunnel.shutdown()` before the process exits.
- **No-log discipline**: the mnemonic, seed and full pubkeys are never logged;
  the account address is printed redacted to an 8-char prefix.
