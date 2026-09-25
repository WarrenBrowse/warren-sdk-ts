#!/bin/sh
# Installs the Warren browser extension's helper for the current user (macOS
# and Linux, arm64 and x86_64). No administrator rights, no runtime: it
# downloads one binary, checks it against the release's SHA256SUMS, and lets
# the binary register itself with every browser it finds.
#
#   curl -fsSL https://github.com/WarrenBrowse/warren-sdk-ts/releases/download/__WARREN_HOST_TAG__/install.sh | sh
#
# Extra extension ids (a development build) pass through to `warren-host
# install`:
#
#   curl -fsSL .../install.sh | sh -s -- --extension-id <id>
#
# Everything runs from the function called on the last line, so a download cut
# short installs nothing.

set -eu

warren_helper_install() {
  tag='__WARREN_HOST_TAG__'
  base="${WARREN_HELPER_BASE_URL:-https://github.com/WarrenBrowse/warren-sdk-ts/releases/download/$tag}"

  die() {
    echo "warren helper: $*" >&2
    exit 1
  }

  case "$(uname -s)" in
    Darwin) asset=warren-host-macos-universal ;;
    Linux)
      case "$(uname -m)" in
        x86_64 | amd64) asset=warren-host-linux-x86_64 ;;
        aarch64 | arm64) asset=warren-host-linux-aarch64 ;;
        *) die "no helper is built for $(uname -m)" ;;
      esac
      ;;
    *) die "this installer is for macOS and Linux; on Windows run install.ps1" ;;
  esac

  command -v curl >/dev/null 2>&1 || die "curl is required"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | awk '{print $1}'; }
  elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
  else
    die "sha256sum or shasum is required to check the download"
  fi

  tmp="$(mktemp -d 2>/dev/null || mktemp -d -t warren-helper)"
  trap 'rm -rf "$tmp"' EXIT INT TERM

  echo "Downloading the Warren helper ($asset)..."
  curl -fsSL "$base/$asset" -o "$tmp/warren-host" || die "download failed: $base/$asset"
  curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

  expected="$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1; exit }' "$tmp/SHA256SUMS")"
  [ -n "$expected" ] || die "SHA256SUMS has no entry for $asset"
  actual="$(sha256 "$tmp/warren-host")"
  [ "$expected" = "$actual" ] || die "checksum mismatch for $asset: refusing to run it"

  chmod 755 "$tmp/warren-host"
  "$tmp/warren-host" install "$@"
}

warren_helper_install "$@"
