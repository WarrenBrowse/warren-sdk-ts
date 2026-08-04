# @warrenbrowse/sdk-core

Pure-TypeScript control plane for the [Warren VPN](https://warrenbrowse.com).
Isomorphic (Node + browser), zero native dependencies. Every frozen format is
pinned byte-for-byte by the shared `warren-vectors`.

This package contains no datapath. It covers identity, the signed account API,
signed-relay-list and multi-hop-directory verification, and exit selection. See
the repository [`SCOPE.md`](../../SCOPE.md) for the full picture.

## Install

```bash
npm install @warrenbrowse/sdk-core
```

## Surface

### Identity

- `generateMnemonic()` fresh 12-word English BIP39 phrase; `seedFromMnemonic(mnemonic)` BIP39 (full validation: wordlist + checksum, throws `WarrenMnemonicError`; empty passphrase) to the 32-byte seed.
- `keyPairFromSeed(seed32)` HKDF-SHA256 (`warren/identity/v1` / `vpn-node-key`) to an Ed25519 keypair; `wipeKeyPair(pair)` zeroizes it.
- `encodeAddress(publicKey)` / `decodeAddress(address)` Warren SS58 (`wb...`, prefix 13295).
- `signRequest(seed, method, path, body, timestamp, nonceHex)` and `signWithKeyPair(...)` deterministic Ed25519 request signing; `signatureHeaders(sig)` builds the four `X-Warren-*` headers.

### Account API

- `new WarrenApiClient({ baseUrl, seed?, transport?, alternativeHosts?, now?, nonce? })`.
- The full `/v1/*` endpoint set: `exits()`, `register()`, `subscription()`, `check()`, `deleteAccount()`, `sessionOpen()`, `sessionClose()`, `submitSupport()`, `initApplePayment()`, `checkApplePayment()`, `reportExitDown()`, `reportPubkeyMismatch()`, `pullPendingVoucher()`, `multihopDirectory()`.
- `HttpTransport` seam with a default isomorphic `fetch` transport; anti-censorship host fallback (primary, alternative hosts, then no-SNI, advancing only on connect failures); typed, redacted `WarrenApiError` / `WarrenTransportError`; `dispose()` zeroizes the signing key.

### Discovery

- `verifySignedRelayList(signedJson, pinnedServerPubkeys?)` verifies the v8 signed list (strict RFC8032 Ed25519 over the canonical payload, version and 7-day validity checks, `deny_unknown_fields`) and resolves dialable relays. Anti-rollback (`generation`) and expiry (`isExpired`) are caller-enforced.
- `verifyMultihopDirectory(json, serverPins?, rootPins?)` verifies the v2 multi-hop directory PKI chain (envelope, operational cert, per-node relay/exit/attestation signatures); `isDirectoryExpired`.
- `acceptSignedRelayList` / `acceptMultihopDirectory` add the full acceptance policy on top of verification: expiry against the wall clock, an anti-rollback `GenerationStore` floor and `ServerKeyStore` TOFU pinning (in-memory implementations provided; supply persistent ones to survive restarts), mirroring the Rust client flow.
- `selectExit` / `selectExitWeighted` / `selectExitForAttempt` with `ExitQuery` (country/city, IP availability, IPv6 egress).

### EdgeConnect (browser WebTransport tier)

The `edge/` module is the wire layer for EdgeConnect: a browser-reachable,
code-initiated-traffic tier that tunnels the Warren multi-hop protocol over
WebTransport (HTTP/3) instead of the native TUN datapath. It is a LOWER
protection tier than the native datapath (a Warren session nested inside
TLS-over-HTTP/3, the nested-TLS shape the native path avoids) and it does
**not** replace the native tunnel; use it only where a page or extension
genuinely cannot run the native datapath.

`acquireTokens` mints the Privacy Pass session tokens (RFC 9578) an `IpRequestV7`
control message carries; `WARREN_EDGE_PORT` (8443) is the well-known port every edge
listens on, and `VerifiedExit.edgeCertSha256` (from the verified multi-hop
directory) is the ephemeral cert pin for the zero-config production path. The
actual WebTransport transport (which needs browser-only APIs) lives in
`@warrenbrowse/sdk-extension`'s `connectEdgeTunnel` / `connectEdgeTunnelToExit`, the
one-call entry points for this tier.

## Secret handling

Seeds and signing keys are secret material. This package never logs identity
material and zeroizes what it can (`seedFromMnemonic` wipes the intermediate
64-byte BIP39 seed; `wipeKeyPair` / `WarrenApiClient.dispose()` clear signing
keys). JS cannot guarantee no copies exist; callers remain responsible for not
persisting seeds in clear.

## License

AGPL-3.0-or-later.
