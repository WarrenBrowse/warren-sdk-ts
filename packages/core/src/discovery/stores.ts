import { WarrenDiscoveryError } from './errors.js';
import {
  type VerifiedDirectory,
  WarrenDirectoryError,
  verifyMultihopDirectory,
} from './multihop.js';
import { type VerifiedRelayList, isExpired } from './relay.js';
import { verifySignedRelayList } from './verify.js';

/**
 * Persists the highest trusted `generation`, the anti-rollback floor.
 *
 * The in-memory default lives only for the process, so anti-rollback resets on
 * every restart: an attacker who can serve HTTP can replay an older but validly
 * signed (and not yet expired) document to a freshly launched client. Supply a
 * persistent implementation (disk, keychain) to survive restarts. Mirrors the
 * Rust `GenerationStore`.
 */
export interface GenerationStore {
  /** The highest generation trusted so far (`0` if none yet). */
  loadFloor(): number;
  /** Records `generation` as trusted; implementations keep the maximum seen. */
  storeFloor(generation: number): void;
}

/**
 * Persists the trusted server pubkey for trust-on-first-use (TOFU) pinning.
 *
 * With no explicit pins, the first verified document's server key is remembered
 * and every later fetch is pinned to it, upgrading trust-on-every-use to
 * trust-on-first-use. Mirrors the Rust `ServerKeyStore`.
 */
export interface ServerKeyStore {
  /** The pinned server pubkey hex, if one has been stored. */
  loadPin(): string | undefined;
  /** Records the server pubkey hex trusted on first use. */
  storePin(serverPubkeyHex: string): void;
}

/** Process-memory {@link GenerationStore}; anti-rollback holds only within one run. */
export class InMemoryGenerationStore implements GenerationStore {
  private floor = 0;

  loadFloor(): number {
    return this.floor;
  }

  storeFloor(generation: number): void {
    if (generation > this.floor) this.floor = generation;
  }
}

/** Process-memory {@link ServerKeyStore}; the TOFU pin holds only within one run. */
export class InMemoryServerKeyStore implements ServerKeyStore {
  private pin: string | undefined;

  loadPin(): string | undefined {
    return this.pin;
  }

  storePin(serverPubkeyHex: string): void {
    this.pin = serverPubkeyHex;
  }
}

/** Policy options for {@link acceptSignedRelayList} / {@link acceptMultihopDirectory}. */
export interface AcceptOptions {
  /** Explicit server pubkey pins (64-char hex). Take precedence over the TOFU store. */
  pins?: readonly string[];
  /** Anti-rollback floor persistence. Omitted: no rollback protection. */
  generationStore?: GenerationStore;
  /** TOFU server-key persistence, consulted only when `pins` is empty. */
  serverKeyStore?: ServerKeyStore;
  /** Wall clock, unix epoch seconds. Defaults to the system clock. */
  now?: number;
}

/** Options for {@link acceptMultihopDirectory}. */
export interface AcceptDirectoryOptions extends AcceptOptions {
  /** Offline ROOT pubkey pins for the operational-cert check (64-char hex). */
  rootPins?: readonly string[];
}

function effectivePins(opts: AcceptOptions): readonly string[] | undefined {
  if (opts.pins && opts.pins.length > 0) return opts.pins;
  const tofu = opts.serverKeyStore?.loadPin();
  return tofu !== undefined ? [tofu] : undefined;
}

function finishAccept(
  opts: AcceptOptions,
  generation: number,
  serverPubkeyHex: string,
  expired: boolean,
  fail: (code: 'expired' | 'rolled_back', message: string) => never,
): void {
  if (expired) fail('expired', 'document is expired');
  const floor = opts.generationStore?.loadFloor() ?? 0;
  if (generation < floor) {
    fail('rolled_back', 'generation is below the trusted anti-rollback floor');
  }
  opts.generationStore?.storeFloor(generation);
  // Trust-on-first-use: with no explicit pins, remember the verified server key
  // the first time so later fetches are pinned to it.
  if ((!opts.pins || opts.pins.length === 0) && opts.serverKeyStore?.loadPin() === undefined) {
    opts.serverKeyStore?.storePin(serverPubkeyHex);
  }
}

/**
 * Verifies a signed relay list and enforces the full acceptance policy the
 * bare verifier cannot: expiry against the wall clock, the anti-rollback
 * generation floor, and TOFU server-key pinning. Mirrors the Rust
 * `WarrenClient::fetch_exits` flow.
 *
 * @throws {WarrenDiscoveryError} with `expired` / `rolled_back` on policy
 *   failures, or any verifier code on a bad document.
 */
export function acceptSignedRelayList(
  signedJson: string,
  options: AcceptOptions = {},
): VerifiedRelayList {
  const verified = verifySignedRelayList(signedJson, effectivePins(options));
  const now = options.now ?? Math.floor(Date.now() / 1000);
  finishAccept(
    options,
    verified.generation,
    verified.serverPubkeyHex,
    isExpired(verified, now),
    (code, message) => {
      throw new WarrenDiscoveryError(code, message);
    },
  );
  return verified;
}

/**
 * Verifies a multi-hop directory and enforces expiry, anti-rollback and TOFU,
 * mirroring the Rust `WarrenClient::fetch_multihop_directory` flow. The
 * directory has its own generation sequence: use a separate
 * {@link GenerationStore} from the relay list's.
 *
 * @throws {WarrenDirectoryError} with `expired` / `rolled_back` on policy
 *   failures, or any verifier code on a bad document.
 */
export function acceptMultihopDirectory(
  json: string,
  options: AcceptDirectoryOptions = {},
): VerifiedDirectory {
  const verified = verifyMultihopDirectory(json, effectivePins(options), options.rootPins);
  const now = options.now ?? Math.floor(Date.now() / 1000);
  finishAccept(
    options,
    verified.generation,
    verified.serverPubkeyHex,
    now >= verified.expiresAt,
    (code, message) => {
      throw new WarrenDirectoryError(code, message);
    },
  );
  return verified;
}
