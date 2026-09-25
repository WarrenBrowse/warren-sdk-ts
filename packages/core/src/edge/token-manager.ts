/**
 * Anonymous session-token manager (Privacy Pass, doc 64), the TypeScript twin of
 * the Rust `warren-api::tokens::TokenManager`.
 *
 * It splits token issuance from token redemption in time, which is the anonymity
 * property at stake: minting at connect time lets the account API correlate the
 * wallet-named issuance with the anonymous session. {@link TokenManager.refresh}
 * mints every published epoch AHEAD of need (call it on unlock and on a coarse
 * timer, NEVER at connect), and {@link TokenManager.sessionStack} /
 * {@link TokenManager.takeCurrentStack} only read pre-minted tokens at connect
 * and never talk to the issuer.
 *
 * Every batch is derived from the wallet (the `blindingKey`), so every client of
 * a wallet holds the same tokens: a manager without a key reads and vends what
 * a store holds but refuses to mint.
 *
 * The settle ledger mirrors the corrected core policy exactly: an epoch is
 * settled (never re-asked) only when it was minted into the store OR when the
 * issuer returns its definitive once-per-account-epoch `already_issued` reject.
 * A transient failure (transport error, 5xx, or a reject that can heal like
 * `not_subscribed`) is deliberately left retryable, so one blip does not
 * silently downgrade a whole epoch to the wallet-signed fallback path.
 */

import { bytesToHex } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';
import { WarrenEdgeError } from './errors.js';
import {
  type TokenIssuerDirectory,
  type TokenTransport,
  currentEpoch,
  mintEpoch,
} from './token-acquire.js';
import { TOKEN_LEN, tokenSerial } from './token.js';

/**
 * The issuer's once-per-account-epoch reject code. The only refusal that is
 * definitive for the rest of the epoch (`warren-api` `token.rs::reject_reason`),
 * hence the only one that settles an epoch client-side.
 */
const REJECT_ALREADY_ISSUED = 'already_issued';

/** Current on-disk bundle schema. */
const BUNDLE_VERSION = 1;

/**
 * Persistence seam for the token store. Implementations hold ONLY redeemable
 * anonymous bearer tokens (base64url-encoded serialized `SessionToken`s) and the
 * published epoch length, NEVER the wallet mnemonic or pubkey: the blind-RSA
 * construction already unlinks these tokens from the account, so a lost or
 * stolen store leaks no identity, only spendable-but-unlinkable credentials.
 *
 * The default is in-memory ({@link InMemoryTokenPersistence}, browser-safe); a
 * Node caller injects a file-backed one so pre-minted tokens survive a process
 * restart (`@warrenbrowse/sdk-node` `fileTokenPersistence`).
 */
export interface TokenPersistence {
  /** The last saved bundle JSON, or `undefined` when nothing is persisted. */
  load(): string | undefined;
  /** Create-or-replace the persisted bundle with `serialized` (JSON). */
  save(serialized: string): void;
}

/** In-memory persistence: the process's own RAM, lost on restart. */
export class InMemoryTokenPersistence implements TokenPersistence {
  private bundle: string | undefined;

  load(): string | undefined {
    return this.bundle;
  }

  save(serialized: string): void {
    this.bundle = serialized;
  }
}

/**
 * A live session's hold on the token it presents ({@link TokenManager.claim}).
 * While held, the token's serial stays out of the manager's
 * {@link TokenManager.sessionStack}; {@link release} gives it back. Releasing
 * twice is harmless.
 */
export interface SessionTokenLease {
  /** Gives the serial back to the manager's stack. */
  release(): void;
}

/** Test and embedding options for a {@link TokenManager}. */
export interface TokenManagerOptions {
  /**
   * Where {@link TokenManager.sessionStack} starts in the epoch's batch. Drawn
   * at random per manager by default: every client of a wallet holds the same
   * batch in the same order, so a fixed start would send all of them to the
   * first serial.
   */
  rotation?: number;
}

interface PersistedBundle {
  v: number;
  /** Published epoch length in seconds; the current epoch is `now / epochSecs`. */
  epochSecs: number;
  /** Serialized tokens (base64url-nopad) keyed by epoch (stringified number). */
  epochs: Record<string, string[]>;
}

/**
 * Keeps a store of pre-minted anonymous tokens topped up and vends the
 * per-session stack presented to the exit.
 *
 * Construct once, inject the wallet-signed {@link TokenTransport}
 * (`WarrenApiClient.tokenTransport()`) and optionally a {@link TokenPersistence}.
 * Any persisted tokens are loaded immediately, so a restarted process can spend
 * them via {@link takeCurrentStack} without a network round-trip.
 */
export class TokenManager {
  private readonly store = new Map<number, Uint8Array[]>();
  /** Epochs settled THIS process (minted, or definitively `already_issued`).
   * Not persisted: the issuer's ledger is the source of truth, so a restart
   * re-asks and a previously minted epoch settles again via `already_issued`. */
  private readonly settled = new Set<number>();
  private directory: TokenIssuerDirectory | undefined;
  /** Epoch length carried across restarts by the persisted bundle, so
   * {@link takeCurrentStack} maps `now` to an epoch before the first refresh. */
  private epochSecs: number | undefined;
  /** Hex serials the live sessions of this manager were admitted on. */
  private readonly held = new Set<string>();
  private readonly rotation: number;
  private readonly blindingKey: Uint8Array | undefined;

  /**
   * `blindingKey` ({@link blindingKeyFromSeed} with the class's purpose:
   * `BLINDING_PURPOSE_SESSION` for {@link WarrenApiClient.tokenTransport},
   * `BLINDING_PURPOSE_BROWSER_PROXY` for the browser-proxy lane) makes the
   * account's batch a function of the wallet. The issuer signs one batch per
   * account, class and epoch and serves it again only to a client sending it
   * bit for bit, so every client of a wallet must derive the same one. It is
   * copied, so the caller may wipe its own buffer.
   *
   * Without a key the manager only reads its store ({@link sessionStack},
   * {@link takeCurrentStack}): {@link refresh} refuses to mint.
   */
  constructor(
    private readonly transport: TokenTransport,
    private readonly persistence: TokenPersistence = new InMemoryTokenPersistence(),
    blindingKey?: Uint8Array,
    options?: TokenManagerOptions,
  ) {
    this.blindingKey = blindingKey === undefined ? undefined : new Uint8Array(blindingKey);
    this.rotation = options?.rotation ?? randomRotation();
    this.loadPersisted();
  }

  /**
   * Fetches the issuer directory, drops spent epochs, and mints every published
   * epoch from the current one forward that has not been settled yet. Per-epoch
   * minting is isolated: one refused or failed epoch never blocks the others,
   * and only a definitive `already_issued` refusal settles an epoch (a transient
   * failure stays retryable for the next tick).
   *
   * Drive this on unlock and on a coarse timer, NEVER at connect time, so
   * issuance timing does not mirror session timing.
   *
   * @throws {WarrenEdgeError} `no_blinding_key` when the manager holds no
   * wallet blinding key (nothing is sent); `token_issuer` only when the
   * directory fetch itself fails or carries an unusable epoch length; a
   * per-epoch mint refusal or transport error is swallowed and left retryable.
   */
  async refresh(nowUnixSecs: number): Promise<void> {
    const blindingKey = this.blindingKey;
    if (blindingKey === undefined) {
      throw new WarrenEdgeError(
        'no_blinding_key',
        'a token manager mints only from a wallet blinding key',
      );
    }
    const directory = await this.transport.getDirectory();
    const current = currentEpoch(directory, nowUnixSecs);

    this.pruneBefore(current);
    for (const epoch of [...this.settled]) {
      if (epoch < current) this.settled.delete(epoch);
    }
    this.directory = directory;
    this.epochSecs = directory.epoch_secs;

    const targets = directory.keys
      .map((k) => k.epoch)
      .filter((epoch) => epoch >= current && !this.settled.has(epoch));

    for (const epoch of targets) {
      try {
        const tokens = await mintEpoch(
          this.transport,
          directory,
          epoch,
          directory.quota_per_epoch,
          blindingKey,
        );
        this.settled.add(epoch);
        const serialized = tokens.map((t) => t.serialize());
        const existing = this.store.get(epoch);
        if (existing) existing.push(...serialized);
        else this.store.set(epoch, serialized);
      } catch (err) {
        if (err instanceof WarrenEdgeError && err.rejectReason === REJECT_ALREADY_ISSUED) {
          // The issuer's once-per-account-epoch ledger already holds this
          // account: re-asking can never succeed, so settle and stop asking.
          this.settled.add(epoch);
        }
        // Anything else proves nothing about the ledger: leave the epoch
        // un-settled so the next refresh retries it, rather than downgrading
        // every session of that epoch to the wallet-signed path on one blip.
      }
    }
    // epochSecs may change even when nothing minted, so always persist.
    this.persist();
  }

  /**
   * Every token of the epoch `now` falls in, serialized, for ONE session to
   * walk in this order: starting at this manager's rotation and leaving out the
   * serials its live sessions hold ({@link claim}). Nothing is consumed and
   * nothing is minted (the Rust `TokenManager::session_stack`).
   *
   * Every client of the wallet holds the same tokens, and an exit refuses a
   * serial another session holds anywhere in the fleet with the same rejection
   * it gives an invalid token. So a session claims the lead, presents it, and on
   * a refusal moves to the next token. An empty stack means no token is free
   * this epoch.
   */
  sessionStack(nowUnixSecs: number): Uint8Array[] {
    const epoch = this.epochAt(nowUnixSecs);
    if (epoch === undefined) return [];
    const tokens = this.store.get(epoch) ?? [];
    if (tokens.length === 0) return [];
    const start = this.rotation % tokens.length;
    return [...tokens.slice(start), ...tokens.slice(0, start)]
      .filter((token) => {
        const serial = tokenSerial(token);
        return serial !== undefined && !this.held.has(bytesToHex(serial));
      })
      .map((token) => new Uint8Array(token));
  }

  /**
   * Holds `token`'s serial for a session about to present it, so no other
   * session of this manager leads with it until the lease is released.
   * `undefined` when a live session already holds it, or when the bytes are no
   * token.
   */
  claim(token: Uint8Array): SessionTokenLease | undefined {
    const serial = tokenSerial(token);
    if (serial === undefined) return undefined;
    const key = bytesToHex(serial);
    if (this.held.has(key)) return undefined;
    this.held.add(key);
    let live = true;
    return {
      release: () => {
        if (!live) return;
        live = false;
        this.held.delete(key);
      },
    };
  }

  /**
   * Pops ONE pre-minted token for the epoch `now` falls in and returns it
   * serialized, removing it from the store. For a credential spent once per
   * epoch (the browser-proxy class); a tunnel session walks
   * {@link sessionStack} instead, since every client of the wallet holds the
   * same session tokens. Returns an empty array when no token is available for
   * this epoch. NEVER mints (no issuer call at connect).
   */
  takeCurrentStack(nowUnixSecs: number): Uint8Array[] {
    const epoch = this.epochAt(nowUnixSecs);
    if (epoch === undefined) return [];
    const tokens = this.store.get(epoch);
    if (!tokens || tokens.length === 0) return [];
    const token = tokens.pop();
    if (tokens.length === 0) this.store.delete(epoch);
    this.persist();
    return token ? [token] : [];
  }

  /**
   * The epoch `nowUnixSecs` falls in, or `undefined` before a refresh (or a
   * persisted bundle) has taught the manager the published epoch length.
   *
   * A caller that must not spend a token per attempt uses this to know how
   * long the token it already holds stays the right one. The browser-proxy
   * tier is the case that needs it: the issuer grants a handful of credentials
   * for the whole epoch, so spending one per reconnect empties the account
   * after a few toggles of the same hour.
   */
  epochAt(nowUnixSecs: number): number | undefined {
    const epochSecs = this.epochSecs;
    if (epochSecs === undefined || epochSecs <= 0) return undefined;
    return Math.floor(nowUnixSecs / epochSecs);
  }

  /** Tokens currently available for `epoch` (test/observability). */
  available(epoch: number): number {
    return this.store.get(epoch)?.length ?? 0;
  }

  /** Epochs that still hold at least one token, ascending. */
  epochs(): number[] {
    return [...this.store.keys()].sort((a, b) => a - b);
  }

  private pruneBefore(minEpoch: number): void {
    for (const epoch of [...this.store.keys()]) {
      if (epoch < minEpoch) this.store.delete(epoch);
    }
  }

  private persist(): void {
    const epochs: Record<string, string[]> = {};
    for (const [epoch, tokens] of this.store) {
      epochs[String(epoch)] = tokens.map((t) => base64urlnopad.encode(t));
    }
    const bundle: PersistedBundle = {
      v: BUNDLE_VERSION,
      epochSecs: this.epochSecs ?? 0,
      epochs,
    };
    this.persistence.save(JSON.stringify(bundle));
  }

  private loadPersisted(): void {
    const raw = this.persistence.load();
    if (raw === undefined) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      // A corrupt bundle fails closed to empty: the next refresh re-mints.
      return;
    }
    if (typeof parsed !== 'object' || parsed === null) return;
    const bundle = parsed as Partial<PersistedBundle>;
    if (bundle.v !== BUNDLE_VERSION) return;
    if (typeof bundle.epochSecs === 'number' && bundle.epochSecs > 0) {
      this.epochSecs = bundle.epochSecs;
    }
    if (typeof bundle.epochs !== 'object' || bundle.epochs === null) return;
    for (const [key, encoded] of Object.entries(bundle.epochs)) {
      const epoch = Number(key);
      if (!Number.isInteger(epoch) || epoch < 0 || !Array.isArray(encoded)) continue;
      const tokens: Uint8Array[] = [];
      for (const b64 of encoded) {
        if (typeof b64 !== 'string') continue;
        let bytes: Uint8Array;
        try {
          bytes = base64urlnopad.decode(b64);
        } catch {
          continue; // Skip a corrupt entry rather than handing bad bytes on.
        }
        if (bytes.length === TOKEN_LEN) tokens.push(bytes);
      }
      if (tokens.length > 0) this.store.set(epoch, tokens);
    }
  }
}

/** A uniformly drawn start for {@link TokenManager.sessionStack}. */
function randomRotation(): number {
  const out = new Uint32Array(1);
  globalThis.crypto.getRandomValues(out);
  return out[0] ?? 0;
}
