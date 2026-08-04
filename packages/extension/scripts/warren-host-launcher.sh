#!/bin/sh
# Native messaging launcher: the browser execs this with the host's stdio
# wired up. The mnemonic comes from the local environment file, never from
# the browser.
set -eu
# Host config, no secrets (the wallet lives in the extension). The XDG path is
# tried first so it works without touching a root-owned ~/.warren.
[ -f "$HOME/.config/warren/host.env" ] && . "$HOME/.config/warren/host.env"
[ -f "$HOME/.warren/host.env" ] && . "$HOME/.warren/host.env"

# The browser spawns hosts with launchd's minimal PATH, so a Homebrew or nvm
# node is invisible; resolve it explicitly (override with WARREN_NODE).
NODE_BIN="${WARREN_NODE:-}"
if [ -z "$NODE_BIN" ]; then
  for candidate in node /opt/homebrew/bin/node /usr/local/bin/node; do
    if command -v "$candidate" >/dev/null 2>&1; then
      NODE_BIN="$candidate"
      break
    fi
  done
fi
[ -n "$NODE_BIN" ] || { echo 'node not found; set WARREN_NODE in ~/.config/warren/host.env' >&2; exit 1; }

exec "$NODE_BIN" "$(dirname "$0")/run-host.mjs"
