# @warrenbrowse/sdk-node

The Node entry for the [Warren VPN](https://warrenbrowse.com) TypeScript SDK.
Re-exports the isomorphic control plane (`@warrenbrowse/sdk-core`) and adds the
two Node-only datapath modes: the in-process proxy mode (`ProxyTunnel`, napi-rs
binding of the native engine) and the system-VPN mode (`WarrendClient`, IPC to
the privileged `warrend` daemon).

## Proxy mode: `ProxyTunnel` (non-root)

A real multi-hop tunnel terminated in-process by the native Warren engine,
exposed as a local SOCKS5 proxy. Live-validated against a real production exit
(see [`native/`](./native)).

```ts
import { ProxyTunnel, isProxyDatapathAvailable } from '@warrenbrowse/sdk-node';

if (isProxyDatapathAvailable()) {
  const tunnel = ProxyTunnel.create({ mnemonic, apiBase, serverPubkeyPin });
  const { socks5 } = await tunnel.connect(); // e.g. 127.0.0.1:1080
  // ... point your client at the proxy ...
  await tunnel.shutdown();
}
```

The full engine surface is exposed: exit selection (`connect({ selector })`),
failover exit lists, lifecycle state events (`onState`), an optional HTTP
CONNECT listener, DAITA, IPv6 requests, a custom DNS server, live `metrics()`
(one-shot datapath), NAT-PMP `forwardPort()`, and `stateDir` persistence of
the anti-rollback floors and the TOFU server pin.

`ProxyTunnel` loads the native addon lazily: importing the package never
requires it, `isProxyDatapathAvailable()` reports capability, and `create()`
throws a typed `WarrenProxyError` (stable `code`, redacted messages) when the
addon is missing or a datapath call fails. The addon is built locally / at
release from the sibling engine checkouts (see
[`native/README.md`](./native/README.md)).

## System-VPN: the `warrend` client

`WarrendClient` drives the privileged `warrend` daemon over its length-prefixed
JSON IPC protocol (4-byte big-endian length prefix + UTF-8 JSON). One connection
is one session; closing the socket tears the tunnel down (fail-closed). The
datapath itself runs in the daemon (root); this client is pure protocol.

```ts
import { WarrendClient } from '@warrenbrowse/sdk-node';

const client = new WarrendClient({
  socketPath: '/run/warren/warrend.sock',
  onState: (state) => console.log('tunnel', state),
  onError: (e) => console.error('warrend', e.kind),
});

client.open();
client.configure({ mnemonic, apiBase: 'https://api.warrenbrowse.com', serverPubkeyPin });
client.connect({ exitPubkeyHex });
// ... later
client.disconnect();
client.close();
```

The frame codec (`encodeFrame`, `FrameDecoder`), request builders and
`parseEvent` are exported for custom transports and testing. `WarrendClient`
accepts a `connectFactory` returning any `Duplex`, so it can be driven against a
fake socket in tests without a running daemon. Lifecycle misuse throws a typed
`WarrendError`; a corrupt daemon frame tears the session down (fail-closed).

## License

AGPL-3.0-or-later.
