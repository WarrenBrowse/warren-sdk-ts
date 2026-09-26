#!/usr/bin/env bash
#
# Codemagic `napi-windows` workflow: the win32-x64 leg of native-prebuilds.yml,
# the native proxy datapath addon built against the pinned engine.
#
#   scripts/ci/codemagic/napi-windows.sh <prepare|build>
set -euo pipefail
source scripts/ci/codemagic/windows-env.sh

crate=packages/node/native/warren-napi

enter_tools() {
    install_rustup
    rustup toolchain install 1.91.0 --profile minimal --target x86_64-pc-windows-msvc
    rustup default 1.91.0
    install_node 20
}

case "${1:?usage: napi-windows.sh <prepare|build>}" in
    prepare)
        check_commit
        timed enter_tools
        timed engine_siblings "$crate" ../../../../..
        ;;
    build)
        enter_tools
        cd "$crate"
        # --dts keeps the generated typings away from the curated index.d.ts
        # (napi's default output path, left empty on cached builds).
        timed pnpm --package=@napi-rs/cli dlx napi build --release --platform \
            --target x86_64-pc-windows-msvc --dts index.generated.d.ts
        src="$(ls warren-napi.*.node | head -1)"
        test -n "$src"
        # napi names it win32-x64-msvc; the loader wants <platform>-<arch>.
        [ "$src" = warren-napi.win32-x64.node ] || mv "$src" warren-napi.win32-x64.node
        cd - > /dev/null
        export_outputs "$crate/warren-napi.win32-x64.node"
        ;;
    *) echo "unknown phase: $1" >&2; exit 2 ;;
esac
