# @warrenbrowse/sdk-web

The browser control-plane entry for the [Warren VPN](https://warrenbrowse.com)
TypeScript SDK.

A web page cannot be a VPN (no raw sockets, no TUN, and browsers reject Warren's
RFC 7250 raw-public-key TLS, so they cannot even dial an exit). This package
therefore exposes only the browser-safe control plane.

## Surface

- `WarrenWebClient` the UNSIGNED `/v1/*` account endpoints: `exits()`,
  `register()` (voucher redemption), `pullPendingVoucher()`, `multihopDirectory()`.
- Address codecs (`encodeAddress`, `decodeAddress`) and discovery verification +
  exit selection (`verifySignedRelayList`, `verifyMultihopDirectory`,
  `selectExit`, ...), all isomorphic and pure.

It deliberately does **not** expose the signing surface (seed derivation, request
signing, the seed-bearing `WarrenApiClient`). A web page must not hold the
identity seed: signed calls (subscription, session, payments, deletion) belong on
a backend using `@warrenbrowse/sdk-node` or `@warrenbrowse/sdk-core`. An advanced
non-custodial wallet can still import `@warrenbrowse/sdk-core` directly.

It cannot mint anonymous tokens either. Issuance is wallet-signed and every
batch is derived from the wallet seed, so a page has neither the signature nor
the blinding key; minting from the CSPRNG instead would reserve the account's
epoch and lock the wallet's other clients (desktop app, extension, Rust SDK) out
of it. A page that needs session tokens receives them from a component that holds
the wallet (a backend on `@warrenbrowse/sdk-core`, or an extension background).

```ts
import { WarrenWebClient } from '@warrenbrowse/sdk-web';

const client = new WarrenWebClient({ baseUrl: 'https://api.warrenbrowse.com' });
const { expires_at } = await client.register({ pubkey_ss58, voucher_secret });
```

## License

AGPL-3.0-or-later.
