#!/usr/bin/env bash
#
# Anti-refragmentation gate for warren-sdk-ts (the TypeScript client SDK).
#
# Runnable form of doc 47 section 5 invariant 6 ("un seul foyer"), against the
# doc-94 single-home catalog (warren-core/docs/94-DEDUP-AUDIT-2026-07-16.md). It
# guards the two TS-side single homes this wave landed:
#   - A7: v7 token minting is decorrelated from connect. The `TokenManager`
#     pre-mints ahead of need; a caller pops a pre-minted stack with
#     `takeCurrentStack()` and NEVER calls `acquireTokens()` at connect (that
#     re-creates the wallet-issuance/session-time correlation, doc 64).
#   - A8: the connection-phase reduction has ONE TS home
#     (`packages/core/src/phase.ts`, the vector-anchored mirror of
#     `warren_contract::phase`); every surface maps-then-delegates to
#     `reducePhase`, none re-implements it.
#
# Cheap (grep only), offline, low-false-positive: it bans a CALL at connect /
# a second DEFINITION while allowing the single home + tests, cites its doc-94
# item, honors an inline `anti-refrag:allow` hatch.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

VIOLATIONS=0

report() {
  VIOLATIONS=$((VIOLATIONS + 1))
  printf '\n[anti-refrag] VIOLATION (%s): %s\n' "$1" "$2"
  printf '%s\n' "$3" | sed 's/^/    /'
}

printf '[anti-refrag] warren-sdk-ts: scanning for regrown single-home twins...\n'

# A7: no `acquireTokens(` CALL in production TS. The only legitimate mention is
# its definition (token-acquire.ts) and its re-export (`acquireTokens,`, no
# paren). A call anywhere in a client surface is a connect-time mint.
a7="$(grep -REn --include='*.ts' \
      --exclude-dir=node_modules --exclude-dir=dist \
      --exclude='*.test.ts' --exclude='*.spec.ts' --exclude='token-acquire.ts' \
      'acquireTokens[[:space:]]*[(]' packages 2>/dev/null | grep -v 'anti-refrag:allow' || true)"
[ -n "$a7" ] && report "doc94 A7" \
  "acquireTokens() called outside the mint home (mint via TokenManager.refresh ahead of need, never at connect)" \
  "$a7"

# A8: `reducePhase` may be DEFINED only in packages/core/src/phase.ts. A second
# reducer (a `function reducePhase` / `reducePhase =` outside the home) is a
# divergent phase contract.
a8="$(grep -REn --include='*.ts' \
      --exclude-dir=node_modules --exclude-dir=dist \
      --exclude='*.test.ts' --exclude='*.spec.ts' \
      'function[[:space:]]+reducePhase|const[[:space:]]+reducePhase|reducePhase[[:space:]]*=' packages 2>/dev/null \
      | grep -v 'packages/core/src/phase.ts' | grep -v 'anti-refrag:allow' || true)"
[ -n "$a8" ] && report "doc94 A8" \
  "second connection-phase reducer (home: packages/core/src/phase.ts; other surfaces map-then-delegate to reducePhase)" \
  "$a8"

if [ "$VIOLATIONS" -gt 0 ]; then
  printf '\n[anti-refrag] FAILED: %d single-home violation(s). Consume the single home, do not re-home here.\n' "$VIOLATIONS"
  exit 1
fi
printf '[anti-refrag] OK: no regrown twins.\n'
