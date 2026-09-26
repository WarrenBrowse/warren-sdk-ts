# Contributing

The development process for `warren-sdk-ts`. For the architecture see
[`ARCHITECTURE.md`](./ARCHITECTURE.md); for current status see [`SCOPE.md`](./SCOPE.md).

## Prerequisites

- Node >= 20, pnpm.
- The golden vectors live in `vectors/` as a git submodule of the private
  `warren-vectors` repo. Clone with submodules (or `git submodule update --init`).
  Outside contributors cannot fetch it; the vector-replay tests then cannot run
  locally, and the org CI replays them on every push.

## Setup and the gates

```bash
git submodule update --init   # the warren-vectors golden vectors (pnpm does not fetch them)
pnpm install
pnpm build            # tsup, dual ESM + CJS + .d.ts per package (BUILD FIRST)
pnpm lint             # biome
pnpm typecheck        # tsc --noEmit per package
pnpm test             # vitest, replays the golden vectors
pnpm coverage         # vitest v8 coverage with thresholds
```

Build first: workspace packages resolve their dependencies' emitted types from
`dist/`, so `pnpm build` must run before `typecheck`/`test` on a clean tree (this
is also the CI order).

All gates must be green before a commit: `pnpm build && pnpm lint && pnpm
typecheck && pnpm test`.

## TDD is mandatory

Red, green, refactor. For every functional change:

- Write the test first; it must fail for the right reason before the production
  code exists.
- Every public function has a direct test; every documented error path is
  triggered by a test. No hollow tests (`expect(true)`, `expect(x).toBe(x)`): a
  test must be able to fail by breaking the production code.
- Frozen wire formats get a vector test that replays the exact shared bytes.

## Golden vectors are the contract

`vectors/` is the shared `warren-vectors` repo, replayed by every sibling SDK and
**minted by warren-core** (the source of truth). Never edit a vector to make a
test pass; fix the code. A vector change is a wire-format break that requires a
schema-version bump.

Adding a new shared vector (the full, proper flow, as done for
`multihop_directory.json`):

1. Mint it authoritatively in **warren-core** (e.g.
   `warren-relay-selector::sign_multihop_directory`) with deterministic test keys.
2. Add the vector file to **warren-vectors** and push.
3. Add a warren-core conformance test (`warren-conformance/tests/<name>.rs`) that
   replays it, and bump warren-core's vectors submodule.
4. Bump this repo's `vectors/` submodule and add a TS test that replays the same
   shared bytes.

## Datapath: validated against reality, not just fakes

Local fake-device tests are necessary but not sufficient for tunnel features. Per
the project rule, the real behavior is validated against a real exit / the real
daemon before any tunnel feature is claimed working.

### Native proxy addon

Requires the Rust toolchain and a sibling `../warren-sdk-rs` checkout (and
`../warrenguard`). See [`packages/node/native/README.md`](./packages/node/native/README.md).

```bash
cd packages/node/native/warren-napi
CARGO_TARGET_DIR=../../../../../warren-sdk-rs/target pnpm --package=@napi-rs/cli dlx napi build --release
```

### Live validations (rooted / real exit)

The mnemonic is supplied at runtime via the environment and never stored.

```bash
pnpm -C packages/node build
# Proxy egress through a real exit:
WARREN_MNEMONIC="<subscribed 12 words>" node packages/node/native/validate-egress.mjs
# System-VPN IPC against the real warrend daemon (root; see warrend dev-sudoers):
sudo -n <warrend> /tmp/warren-it.sock &
WARREN_MNEMONIC="<...>" WARREND_SOCK=/tmp/warren-it.sock node packages/node/native/validate-warrend.mjs
```

## Coverage

`pnpm coverage` runs vitest with the v8 provider over `packages/*/src` and
enforces thresholds (see `vitest.config.ts`). The proxy facade is excluded
because it only runs with the native addon, which is absent in CI.

## CI

`.github/workflows/ci.yml` runs on GitHub-hosted Linux and Windows runners and
the org's self-hosted macOS runner, plus a coverage job. The private `warren-vectors` submodule
is fetched over HTTPS with the repo-level `VECTORS_TOKEN` secret (ideally a
fine-grained PAT with `contents:read` on `warren-sdk-ts` + `warren-vectors`). The
native addon is **not** built in CI: the private engine uses sibling path deps to
`warrenguard` that a fresh CI checkout cannot reproduce; it is built locally and
at release time.

## Conventions

- English only in code, comments, identifiers, commit messages.
- Never use the em-dash (`—`) or en-dash (`–`): use a comma, colon, period, or
  hyphen for ranges.
- Commit messages: a subject line only (no body, no `Co-Authored-By`).
- Comments explain the non-obvious why (an invariant, a subtle reason), not step
  narration.
- TSDoc on every exported symbol. Secrets (seeds, signing keys) are never logged;
  the browser package holds no signing key by default.

## License

AGPL-3.0-or-later. The full text is in [LICENSE](./LICENSE).
