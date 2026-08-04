# @warrenbrowse/sdk

The app-facing entry of the [Warren VPN](https://warrenbrowse.com) TypeScript
SDK. Today it re-exports the full isomorphic control plane of
[`@warrenbrowse/sdk-core`](../core) under the stable, short package name apps
import.

For the VPN datapath, depend on the runtime-specific package directly:

- Node / Electron main: [`@warrenbrowse/sdk-node`](../node) (`ProxyTunnel`,
  `WarrendClient`).
- Browser: [`@warrenbrowse/sdk-web`](../web) (`WarrenWebClient`, control plane
  only).

See the repository [`README.md`](../../README.md) for a quickstart and
[`ARCHITECTURE.md`](../../ARCHITECTURE.md) for the package layout.

## License

AGPL-3.0-or-later.
