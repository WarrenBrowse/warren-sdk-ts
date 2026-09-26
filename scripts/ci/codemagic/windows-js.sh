#!/usr/bin/env bash
#
# ci.yml `js-windows`: the Windows leg of the js job, with the same commands
# as the Linux and macOS legs.
#
#   scripts/ci/codemagic/windows-js.sh <prepare|checks>
set -euo pipefail
source scripts/ci/codemagic/windows-env.sh

case "${1:?usage: windows-js.sh <prepare|checks>}" in
    prepare)
        check_commit
        # The vitest suites replay the golden vectors.
        git submodule update --init --recursive
        timed install_node 20
        timed pnpm install --frozen-lockfile
        ;;
    checks)
        install_node 20
        timed pnpm build
        timed pnpm lint
        timed pnpm typecheck
        timed pnpm test
        pnpm --filter @warrenbrowse/sdk-extension build:example
        node --check examples/vpn-desk/server.mjs
        node --check examples/vpn-desk/public/app.js
        node --check packages/extension/example/background.js
        node --check packages/extension/example/popup.js
        node -e "JSON.parse(require('node:fs').readFileSync('packages/extension/example/manifest.json','utf8'))"
        ;;
    *) echo "unknown phase: $1" >&2; exit 2 ;;
esac
