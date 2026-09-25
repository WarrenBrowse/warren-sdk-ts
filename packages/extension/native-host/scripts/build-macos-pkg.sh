#!/bin/sh
# Builds the macOS universal helper binary and the Warren-Helper.pkg that
# installs it.
#
#   scripts/build-macos-pkg.sh <arm64 binary> <x86_64 binary> <version> <out dir>
#
# Writes <out dir>/warren-host-macos-universal and <out dir>/Warren-Helper.pkg.
#
# The package carries no payload: the universal binary rides in its scripts,
# and the postinstall runs `warren-host install` as the user sitting at the
# console, so the package lands the helper exactly where every other route
# does (the user's Library, per-user browser registrations) and leaves nothing
# system-wide behind. The package is unsigned: no Developer ID certificate
# exists yet, so Gatekeeper asks the user to confirm it (right click, Open).

set -eu

[ "$#" -eq 4 ] || { echo "usage: $0 <arm64 binary> <x86_64 binary> <version> <out dir>" >&2; exit 2; }
arm64="$1"
x86_64="$2"
version="$3"
out="$4"

mkdir -p "$out"
universal="$out/warren-host-macos-universal"
lipo -create "$arm64" "$x86_64" -output "$universal"
chmod 755 "$universal"
lipo "$universal" -verify_arch arm64 x86_64

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/scripts" "$work/packages"
cp "$universal" "$work/scripts/warren-host"

cat > "$work/scripts/postinstall" <<'EOF'
#!/bin/sh
# Registers the helper for the user at the console, as that user: the
# installer itself runs as root, and a root-owned copy in root's home would
# serve nobody.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
user="$(stat -f%Su /dev/console)"
if [ -z "$user" ] || [ "$user" = "root" ] || [ "$user" = "loginwindow" ]; then
  echo "warren helper: no user is logged in at the console; run 'warren-host install' as the user" >&2
  exit 0
fi
home="$(dscl . -read "/Users/$user" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')"
if [ "$(id -u)" -eq 0 ]; then
  exec sudo -u "$user" -H env HOME="$home" "$here/warren-host" install
fi
exec "$here/warren-host" install
EOF
chmod 755 "$work/scripts/postinstall"

pkgbuild \
  --nopayload \
  --scripts "$work/scripts" \
  --identifier com.warrenbrowse.helper \
  --version "$version" \
  "$work/packages/helper.pkg"

cat > "$work/distribution.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>Warren Helper</title>
  <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>
  <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
  <choices-outline>
    <line choice="default">
      <line choice="com.warrenbrowse.helper"/>
    </line>
  </choices-outline>
  <choice id="default"/>
  <choice id="com.warrenbrowse.helper" visible="false">
    <pkg-ref id="com.warrenbrowse.helper"/>
  </choice>
  <pkg-ref id="com.warrenbrowse.helper" version="$version" onConclusion="none">helper.pkg</pkg-ref>
</installer-gui-script>
EOF

productbuild \
  --distribution "$work/distribution.xml" \
  --package-path "$work/packages" \
  "$out/Warren-Helper.pkg"

ls -l "$universal" "$out/Warren-Helper.pkg"
