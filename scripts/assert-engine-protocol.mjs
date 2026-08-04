#!/usr/bin/env node
// Pre-publish gate: prove the WarrenGuard engine compiled into the napi addon
// speaks a live-fleet wire protocol. The TS control plane is protocol-agnostic
// and the napi addon is built locally / at release (not in CI), so a green
// `pnpm test` never exercises the bundled datapath. A stale engine that still
// speaks the pre-v5 mutual-TLS handshake would ship `@warrenbrowse/sdk-node`
// with a datapath that silently cannot connect to the now-all-v5+ exit fleet.
// This gate blocks that.
//
// It reads the authoritative wire constant (`PROTOCOL_VERSION` in
// warrenguard-wire) directly, NOT a commit hash: engine history is periodically
// squashed for the public snapshot, which orphans any hardcoded rev and would
// break a hash-based gate for every pin (it did: the old `f94aabc` sentinel is
// unreachable after the 2026-07-13 squash). The constant survives rewrites and
// is exactly what compiles into the addon.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

// The napi build [patch]es the warrenguard git-dep onto this sibling working
// tree (see packages/node/native/warren-napi/Cargo.toml), so that tree is what
// actually compiles into the addon.
const ENGINE_REPO = resolve(repoRoot, '..', 'warrenguard');
const WIRE_LIB = 'crates/warrenguard-wire/src/lib.rs';

// Recorded engine intent, used only to flag a stale/off-history pin. The build
// consumes the working tree above, not this rev, so it is advisory here.
const PIN_FILE = resolve(repoRoot, 'packages/node/native/warren-napi/.warrenguard-engine-rev');

// The live exit fleet dropped v4 (TLS mutual-auth, an active-probing tell) at
// the v5 cutover; every prod exit now speaks >= v5 (v6 default, v7 dual-accept).
// An addon below this floor cannot complete the in-band client-auth handshake.
const MIN_FLEET_PROTOCOL = 5;

function fail(message) {
  console.error(`assert-engine-protocol: FAIL: ${message}`);
  process.exit(1);
}

function parseProtocolVersion(source, origin) {
  const m = source.match(/pub const PROTOCOL_VERSION\s*:\s*u8\s*=\s*(\d+)/);
  if (!m) {
    fail(`could not find PROTOCOL_VERSION in the engine wire crate (${origin})`);
  }
  return Number(m[1]);
}

function readPinnedRev() {
  if (!existsSync(PIN_FILE)) return null;
  const rev = readFileSync(PIN_FILE, 'utf8').trim();
  if (!/^[0-9a-f]{7,40}$/.test(rev)) {
    fail(`engine pin is not a git rev: "${rev}" (in ${PIN_FILE})`);
  }
  return rev;
}

function gitAvailable() {
  if (!existsSync(resolve(ENGINE_REPO, '.git'))) return false;
  try {
    execFileSync('git', ['-C', ENGINE_REPO, 'rev-parse', 'HEAD'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

// Source of truth, in priority order:
//   1. the on-disk wire crate, which the [patch] compiles into the addon (this
//      is what actually ships, dirty tree included);
//   2. the pinned rev via git, when the working tree is unavailable.
let source;
let origin;
const onDisk = resolve(ENGINE_REPO, WIRE_LIB);
const pinnedRev = readPinnedRev();

if (existsSync(onDisk)) {
  source = readFileSync(onDisk, 'utf8');
  origin = onDisk;
} else if (pinnedRev && gitAvailable()) {
  try {
    source = execFileSync('git', ['-C', ENGINE_REPO, 'show', `${pinnedRev}:${WIRE_LIB}`], {
      encoding: 'utf8',
    });
    origin = `${pinnedRev}:${WIRE_LIB}`;
  } catch {
    fail(`cannot read ${WIRE_LIB} at pinned rev ${pinnedRev} (wrong path or unknown rev)`);
  }
} else {
  fail(
    `no warrenguard checkout to verify the engine protocol (looked for ${onDisk}); the addon is built from this sibling, so it must be present to publish`,
  );
}

const version = parseProtocolVersion(source, origin);
if (version < MIN_FLEET_PROTOCOL) {
  fail(
    `engine wire PROTOCOL_VERSION is ${version} (< ${MIN_FLEET_PROTOCOL}): this datapath predates the in-band client-auth cutover and cannot connect to the live exit fleet (${origin})`,
  );
}

// Advisory pin hygiene: a recorded pin that is not part of the engine's real
// history (orphaned by a rewrite, or a typo) means the intent file no longer
// tracks anything. Warn, do not block: what ships is verified above.
if (pinnedRev && gitAvailable()) {
  try {
    execFileSync('git', ['-C', ENGINE_REPO, 'merge-base', '--is-ancestor', pinnedRev, 'HEAD'], {
      stdio: 'ignore',
    });
  } catch {
    console.warn(
      `assert-engine-protocol: WARN: recorded pin ${pinnedRev} is not an ancestor of warrenguard HEAD (stale or orphaned intent file); the build used the working tree above`,
    );
  }
}

console.log(
  `assert-engine-protocol: OK: engine wire PROTOCOL_VERSION is ${version} ` +
    `(>= ${MIN_FLEET_PROTOCOL}) [${origin}]`,
);
process.exit(0);
