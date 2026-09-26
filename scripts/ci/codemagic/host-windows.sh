#!/usr/bin/env bash
#
# release-host.yml `build-windows`: the windows-x86_64 lane. Tests and builds
# warren-host with a static CRT (no MSVC runtime to install: the downloaded
# .exe runs as is), checks that it names its release and channel, and ships it
# as Warren-Helper-Setup.exe.
#
#   scripts/ci/codemagic/host-windows.sh <prepare|build>
set -euo pipefail
source scripts/ci/codemagic/windows-env.sh

crate=packages/extension/native-host
target=x86_64-pc-windows-msvc
export WARREN_PRODUCT_ENV="$WARREN_CHANNEL"
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-C target-feature=+crt-static"

enter_tools() {
    install_rustup
    (cd "$crate" && rustup toolchain install && rustup target add "$target")
}

case "${1:?usage: host-windows.sh <prepare|build>}" in
    prepare)
        check_commit
        timed enter_tools
        timed engine_siblings "$crate" ../../../..
        ;;
    build)
        enter_tools
        cd "$crate"
        bin="target/$target/release/warren-host.exe"
        timed cargo test --locked --release --target "$target"
        timed cargo build --locked --release --target "$target"
        test -f "$bin" || { echo "::error::no binary at $bin" >&2; exit 1; }
        line="$("$bin" --version | tr -d '\r')"
        [ "$line" = "warren-host $WARREN_VERSION ($WARREN_CHANNEL channel)" ] \
            || { echo "::error::--version says: $line" >&2; exit 1; }
        cp "$bin" Warren-Helper-Setup.exe
        cd - > /dev/null
        export_outputs "$crate/Warren-Helper-Setup.exe"
        ;;
    *) echo "unknown phase: $1" >&2; exit 2 ;;
esac
