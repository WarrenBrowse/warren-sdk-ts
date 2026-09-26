# shellcheck shell=bash
#
# Build environment for a Codemagic windows_x2 machine (Git Bash), sourced by
# the scripts/ci/codemagic/*.sh entry points. Every build starts on a fresh VM
# (Windows Server 2022, x64, VS 2022 17.14, Git, Python 3.9, Node 20.12) with
# no Rust and no pnpm, so both are installed here.
#
# codemagic.yaml caches downloads only, for the addon and helper workflows
# (windows-js has none, it did not pay): rustup's toolchains, ~/.cargo/bin,
# cargo's registry and git sources, the Node release in use, corepack's pnpm
# and the pnpm store. A shipped addon or helper always compiles from a clean
# target/. `scripts/codemagic-cache.sh clear warren-sdk-ts` in the workspace
# empties the caches.

set -euo pipefail

# The step's PowerShell hands bash a stdin pipe it never closes; a child that
# reads it (Windows PowerShell 5.1 does, before running -Command) waits forever.
exec < /dev/null


# Codemagic's PowerShell profile (posh-sshell, Start-SshAgent, the build's
# variables) makes every Windows PowerShell that loads it hold its caller's
# output open: `x="$(powershell.exe -Command 'Write-Output ok')"` never
# returned, the same call with -NoProfile did in 2 s (self-test of
# 2026-09-26). The build starts PowerShell without -NoProfile in places it
# does not own (msbuild's NMake steps, tool scripts), and whatever waits for
# that output then hangs with no CPU. Nothing in these builds needs the
# profile, so it is moved aside for the rest of the VM's life.
neutralize_powershell_profile() {
    local profile
    profile="$(powershell.exe -NoProfile -NonInteractive -Command 'Write-Output $PROFILE.CurrentUserCurrentHost' | tr -d '\r')"
    if [ -n "$profile" ] && [ -f "$(cygpath -u "$profile")" ]; then
        mv -f "$(cygpath -u "$profile")" "$(cygpath -u "$profile").off"
        echo "PowerShell profile moved aside: $profile"
    fi
}
neutralize_powershell_profile

CM_TOOLS="${CM_TOOLS:-$HOME/cm-tools}"
mkdir -p "$CM_TOOLS"

fetch() { # fetch <url> <dest>
    curl -fsSL --retry 5 --retry-all-errors --connect-timeout 30 -o "$2" "$1"
}

# Run one setup phase and say how long it took, so the effect of the cache
# can be read off any build log.
timed() { # timed <function> [args...]
    local start=$SECONDS
    "$@"
    echo "[timing] $1: $((SECONDS - start))s"
}

check_commit() {
    local head
    head="$(git rev-parse HEAD)"
    if [ "$head" != "$WARREN_SHA" ]; then
        echo "::error::checked out $head but the build was asked for $WARREN_SHA" >&2
        return 1
    fi
}

install_rustup() {
    export PATH="$HOME/.cargo/bin:$PATH"
    if ! command -v rustup > /dev/null 2>&1; then
        fetch https://win.rustup.rs/x86_64 "$CM_TOOLS/rustup-init.exe"
        "$CM_TOOLS/rustup-init.exe" -y --default-toolchain none --profile minimal --no-modify-path
        rm -f "$CM_TOOLS/rustup-init.exe"
    fi
    # No toolchain here: the repo root has no rust-toolchain.toml, and each
    # crate names its own (native-host's file, warren-napi's 1.91.0).
    rustup --version
}

# Node from nodejs.org: <major> takes the newest release of that line, as
# actions/setup-node does for `node-version: 20`. pnpm then comes from
# corepack, at the version package.json's packageManager field pins.
install_node() { # install_node <major>
    local sum name old
    fetch "https://nodejs.org/dist/latest-v$1.x/SHASUMS256.txt" "$CM_TOOLS/node.sums"
    name="$(sed -n -E 's/^[0-9a-f]{64}  (node-v[0-9.]+-win-x64)\.zip$/\1/p' "$CM_TOOLS/node.sums")"
    test -n "$name" || { echo "::error::no win-x64 zip in node $1 SHASUMS256" >&2; return 1; }
    # The newest release of the line is the one kept; an older one restored
    # from the cache is dropped.
    for old in "$CM_TOOLS"/node-v*-win-x64; do
        [ -e "$old" ] && [ "$old" != "$CM_TOOLS/$name" ] && rm -rf "$old"
    done
    if [ -d "$CM_TOOLS/$name" ]; then
        echo "$name: from cache"
    else
        fetch "https://nodejs.org/dist/latest-v$1.x/$name.zip" "$CM_TOOLS/node.zip"
        sum="$(grep " $name.zip\$" "$CM_TOOLS/node.sums" | cut -d' ' -f1)"
        echo "$sum  $CM_TOOLS/node.zip" | sha256sum -c -
        7z x -y -o"$(cygpath -w "$CM_TOOLS")" "$(cygpath -w "$CM_TOOLS/node.zip")" > /dev/null
        rm -f "$CM_TOOLS/node.zip"
    fi
    rm -f "$CM_TOOLS/node.sums"
    export PATH="$CM_TOOLS/$name:$PATH"
    export npm_config_store_dir="$HOME/cm-pnpm-store"
    corepack enable
    node --version
    pnpm --version
}

# The engine repos the native crates compile against, as siblings of this
# checkout: warren-sdk-rs at the rev both crates pin (they must agree), then
# warrenguard and warren-contract at the revs that commit names. The crate
# given is pointed at the checked-out warren-sdk-rs through the gitignored
# override a developer uses, so cargo never fetches the engine itself.
engine_siblings() { # engine_siblings <crate dir> <relative path to the sibling parent>
    local pin='s/^warren-sdk = \{ git = "https:\/\/github.com\/WarrenBrowse\/warren-sdk-rs.git", rev = "([0-9a-f]{40})" \}$/\1/p'
    local host napi
    host="$(sed -n -E "$pin" packages/extension/native-host/Cargo.toml)"
    napi="$(sed -n -E "$pin" packages/node/native/warren-napi/Cargo.toml)"
    test -n "$host" || { echo "::error::no warren-sdk rev pin in native-host/Cargo.toml" >&2; return 1; }
    test "$host" = "$napi" || { echo "::error::native-host pins $host but warren-napi pins $napi" >&2; return 1; }
    printf '%s\n' "$host" > "$CM_TOOLS/sdk-pin"
    checkout_sibling warren-sdk-rs "$CM_TOOLS/sdk-pin"
    checkout_sibling warrenguard ../warren-sdk-rs/.warrenguard-version
    checkout_sibling warren-contract ../warren-sdk-rs/.warren-contract-version
    mkdir -p "$1/.cargo"
    printf '%s\n' '[patch."https://github.com/WarrenBrowse/warren-sdk-rs.git"]' \
        "warren-sdk = { path = \"$2/warren-sdk-rs/crates/warren-sdk\" }" > "$1/.cargo/config.toml"
}
# Clone a public WarrenBrowse sibling next to this checkout, at its pin.
checkout_sibling() { # checkout_sibling <repo> <pin file>
    local repo="$1" sha
    sha="$(tr -d '[:space:]' < "$2")"
    if ! printf '%s' "$sha" | grep -Eq '^[0-9a-f]{40}$'; then
        echo "::error::$2 must hold one full commit SHA, got '$sha'" >&2
        return 1
    fi
    rm -rf "../$repo"
    git clone --quiet --filter=blob:none "https://github.com/WarrenBrowse/$repo.git" "../$repo"
    git -C "../$repo" checkout --quiet --detach "$sha"
    echo "$repo @ $(git -C "../$repo" rev-parse HEAD)"
}

# Write outputs flat into cm-out/ with the checksum list the GitHub proxy
# (warren-app .github/actions/codemagic-build) verifies before publishing.
export_outputs() { # export_outputs <file>...
    rm -rf cm-out
    mkdir -p cm-out
    cp -- "$@" cm-out/
    (cd cm-out && sha256sum -- * > codemagic.sha256)
    cat cm-out/codemagic.sha256
}
