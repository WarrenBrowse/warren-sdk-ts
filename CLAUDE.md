# warren-sdk-ts: rules for Claude Code

Standalone TypeScript client SDK for the Warren VPN, a clean-room, wire-compatible
sibling of `warren-sdk-rs` (the Rust reference) and `warren-sdk-dart`. Read
`ARCHITECTURE.md` for the canonical architecture (the control-plane/datapath
split, per-environment capabilities, the napi-rs and warrend bindings),
`CONTRIBUTING.md` for the workflow and gates, and `SCOPE.md` for current status.

> Shared Warren rules (single source of truth: WarrenBrowse/warren-workspace).
> They resolve when this repo is checked out inside the workspace (mani sync);
> cloned standalone, the imports just warn harmlessly.
@../shared/rules/00-conventions.md
@../shared/rules/10-tdd.md
@../shared/rules/20-errors-secrets.md
@../shared/rules/30-git-commits.md
@../shared/rules/40-wire-vectors.md

## Prime directive: clean-room, native datapath

- **Standalone.** Never depends on `warren-core`; `../warren-core` is read-only
  reference material.
- **The datapath is never reimplemented in TypeScript.** Only the control plane
  (identity, signing, account API, discovery, exit selection) is pure TS. The
  datapath is always reused as native code: the napi-rs addon binding
  `warren-sdk` (proxy mode) and the `warrend` daemon IPC (system-VPN). The
  rationale and the full layering are in `ARCHITECTURE.md`.
- **Golden vectors** live in `vectors/`, the private `warren-vectors` submodule,
  minted by warren-core. The shared wire-vectors rule applies; the flow for
  adding a new shared vector is in `CONTRIBUTING.md`.

## Packages (pnpm workspace: `packages/*` + `examples/*`)

| package | role |
|---|---|
| `@warrenbrowse/sdk-core` | isomorphic pure-TS control plane: identity, SS58, signing, account API, discovery, selection |
| `@warrenbrowse/sdk` | app-facing isomorphic facade, re-exports the control plane |
| `@warrenbrowse/sdk-node` | Node/Electron datapath: `ProxyTunnel` (napi-rs engine) + `WarrendClient` (warrend IPC) |
| `@warrenbrowse/sdk-web` | browser control plane, no signing key in the page |
| `@warrenbrowse/sdk-extension` | MV3 browser-extension VPN (`chrome.proxy` + native messaging) plus its Node native host |

## Gates (the CI order, `.github/workflows/ci.yml`)

```bash
git submodule update --init   # warren-vectors; pnpm does not fetch it
pnpm install
pnpm build       # FIRST: workspace deps resolve types from dist/, so build precedes typecheck/test on a clean tree
pnpm lint        # biome
pnpm typecheck   # tsc --noEmit per package
pnpm test        # vitest, replays the golden vectors
```

All green before any commit; CI adds `pnpm coverage` (v8, thresholds enforced).
The native addon (`packages/node/native`) is not built in CI (sibling path deps
to the private engine); build it locally per `packages/node/native/README.md`.
Datapath features are additionally validated against a real exit / the real
daemon: `CONTRIBUTING.md`, "Live validations".

## Downstream consumer

`warren-extension` consumes these packages via `link:../warren-sdk-ts/packages/*`
and its CI clones this repo, so a breaking change to a package's public surface
breaks that repo. Keep it green, or fix it in the same push, when you change a
published surface.
