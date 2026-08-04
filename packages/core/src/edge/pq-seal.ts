/**
 * The Warren `/v2` post-quantum multi-hop seal: X-Wing hybrid KEM once per
 * session, then per-packet keys via HKDF-SHA256 over the hybrid shared secret,
 * each feeding a ChaCha20-Poly1305 under a FIXED all-zero nonce. Byte-for-byte
 * compatible with the Rust `warrenguard-multihop` `pq_session.rs`
 * (`PqClientSession` / `PqExitSession`), pinned by `vectors/pq_hpke_seal_v2.json`.
 *
 * The seal MIRRORS the classical {@link WarrenClientSession} one-for-one but
 * swaps DHKEM(X25519) for X-Wing and the HPKE exporter for a plain HKDF key
 * schedule under a `/v2`-distinct salt/label, so the two datapaths are
 * cryptographically domain-separated and never derive the same per-packet key.
 * Everything else is identical to `/v1`: the zero nonce is safe only because
 * each `(epoch, seq)` yields a unique key, and forward vs reverse keys are kept
 * distinct by a trailing direction tag on the reverse export info.
 *
 * PQ is opt-in and dormant by default: nothing here runs unless a caller
 * constructs a PQ session, so the `/v1` datapath is byte-for-byte unchanged.
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { expand, extract } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';
import { WARREN_HPKE_VERSION_V2, type WarrenMultihopFrameV2 } from './frame-v2.js';
import {
  type XWingRecipientPublicKey,
  type XWingRecipientSecretKey,
  xwingDecapsulate,
  xwingEncapsulate,
  xwingEncapsulateRandom,
} from './xwing.js';

/** HKDF-SHA256 salt for the `/v2` PQ key schedule; must equal the Rust
 * `WARREN_PQ_HPKE_SALT_V2`. */
const WARREN_PQ_HPKE_SALT_V2 = utf8ToBytes('warren/multihop/v2/pq-hkdf-salt');
/** Prefix of BOTH the AEAD AAD and the per-packet HKDF info; must equal the Rust
 * `WARREN_PQ_HPKE_AAD_V2`. Deliberately distinct from the `/v1` AAD. */
const WARREN_PQ_HPKE_AAD_V2 = utf8ToBytes('warren/multihop/v2/pq-aad');

const PER_PACKET_KEY_LEN = 32;
const NONCE_ZERO_12 = new Uint8Array(12);
const AEAD_TAG_LEN = 16;
const EXIT_ID_LEN = 16;
/** Trailing byte on the reverse (exit -> client) export info; must equal the Rust
 * `DIRECTION_TAG_REVERSE`. Keeps forward and reverse per-packet keys distinct
 * even when `(epoch, seq)` repeat across directions. */
const DIRECTION_TAG_REVERSE = 0x02;

function beU32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n >>> 0, false);
  return out;
}

function beU64(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt.asUintN(64, n), false);
  return out;
}

/** Per-packet HKDF export info: `WARREN_PQ_HPKE_AAD_V2 || epoch_be32 || seq_be64`
 * (37 bytes). Reuses the AAD prefix, carries no exit_id (exit_id lives only in
 * the AAD). */
function composeExportInfo(epoch: number, seq: bigint): Uint8Array {
  const out = new Uint8Array(WARREN_PQ_HPKE_AAD_V2.length + 4 + 8);
  out.set(WARREN_PQ_HPKE_AAD_V2, 0);
  out.set(beU32(epoch), WARREN_PQ_HPKE_AAD_V2.length);
  out.set(beU64(seq), WARREN_PQ_HPKE_AAD_V2.length + 4);
  return out;
}

/** Reverse-direction export info: the forward info plus a trailing
 * {@link DIRECTION_TAG_REVERSE} byte (38 bytes). */
function composeExportInfoReverse(epoch: number, seq: bigint): Uint8Array {
  const fwd = composeExportInfo(epoch, seq);
  const out = new Uint8Array(fwd.length + 1);
  out.set(fwd, 0);
  out[fwd.length] = DIRECTION_TAG_REVERSE;
  return out;
}

/** AEAD AAD: `WARREN_PQ_HPKE_AAD_V2 || exit_id(16) || epoch_be32 || seq_be64`
 * (53 bytes). Binds the ciphertext to its exit and its `(epoch, seq)` slot. */
function composeAad(exitId: Uint8Array, epoch: number, seq: bigint): Uint8Array {
  const out = new Uint8Array(WARREN_PQ_HPKE_AAD_V2.length + EXIT_ID_LEN + 4 + 8);
  let o = 0;
  out.set(WARREN_PQ_HPKE_AAD_V2, o);
  o += WARREN_PQ_HPKE_AAD_V2.length;
  out.set(exitId, o);
  o += EXIT_ID_LEN;
  out.set(beU32(epoch), o);
  o += 4;
  out.set(beU64(seq), o);
  return out;
}

/** Derive a per-packet key: `HKDF-Expand(HKDF-Extract(salt, ss), info, 32)`.
 * PRK is extracted with the `/v2` salt over the X-Wing shared secret (IKM). */
function derivePerPacketKey(sharedSecret: Uint8Array, info: Uint8Array): Uint8Array {
  const prk = extract(sha256, sharedSecret, WARREN_PQ_HPKE_SALT_V2);
  return expand(sha256, prk, info, PER_PACKET_KEY_LEN);
}

function sameExit(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/** Retained previous-epoch X-Wing secret for the rekey overlap window. */
interface PqPendingOldEpoch {
  sharedSecret: Uint8Array;
  epoch: number;
}

/**
 * Sender (client) side of a `/v2` post-quantum multihop session. Holds the
 * X-Wing hybrid shared secret and the ciphertext halves every frame of the
 * epoch carries. Mirrors the Rust `PqClientSession`.
 */
export class WarrenPqClientSession {
  private pendingOldEpoch: PqPendingOldEpoch | undefined;

  private constructor(
    private readonly recipient: XWingRecipientPublicKey,
    private sharedSecret: Uint8Array,
    /** The 16-byte exit routing tag. */
    readonly exitId: Uint8Array,
    /** X25519 ephemeral public (`ct_X`), carried in `encapsulated_key`. */
    private currentEncapsulatedKey: Uint8Array,
    /** ML-KEM ciphertext (`ct_M`), carried in `pq_ct` on the setup/rekey frame. */
    private currentPqCt: Uint8Array,
    private currentEpoch: number,
  ) {
    if (exitId.length !== EXIT_ID_LEN) {
      throw new RangeError(`exitId must be ${EXIT_ID_LEN} bytes`);
    }
  }

  /**
   * Set up a PQ sender session against the exit's X-Wing recipient public key
   * (its ML-KEM-768 key + static X25519 key, both from the SIGNED descriptor).
   * Runs the X-Wing encapsulation once, drawing fresh CSPRNG randomness.
   */
  static create(recipient: XWingRecipientPublicKey, exitId: Uint8Array): WarrenPqClientSession {
    const enc = xwingEncapsulateRandom(recipient);
    return new WarrenPqClientSession(
      recipient,
      enc.sharedSecret,
      exitId,
      enc.ciphertext.x25519Ct,
      enc.ciphertext.mlkemCt,
      0,
    );
  }

  /**
   * Deterministic constructor for golden-vector generation: encapsulate with the
   * exact `mSeed` (ML-KEM message) and `ephXSeed` (X25519 ephemeral) instead of
   * drawing them from the CSPRNG, so the emitted frame bytes are reproducible.
   * NEVER use in production (a real session MUST draw fresh randomness via
   * {@link WarrenPqClientSession.create}).
   */
  static createDeterministic(
    recipient: XWingRecipientPublicKey,
    exitId: Uint8Array,
    mSeed: Uint8Array,
    ephXSeed: Uint8Array,
  ): WarrenPqClientSession {
    const enc = xwingEncapsulate(recipient, mSeed, ephXSeed);
    return new WarrenPqClientSession(
      recipient,
      enc.sharedSecret,
      exitId,
      enc.ciphertext.x25519Ct,
      enc.ciphertext.mlkemCt,
      0,
    );
  }

  /** The X25519 ephemeral public (`ct_X`) carried on every frame of this epoch. */
  get encapsulatedKey(): Uint8Array {
    return this.currentEncapsulatedKey;
  }

  /** The ML-KEM-768 ciphertext (`ct_M`) carried in `pq_ct` on the setup frame. */
  get pqCt(): Uint8Array {
    return this.currentPqCt;
  }

  /** Current epoch counter (starts at 0, +1 per {@link WarrenPqClientSession.rekey}). */
  get epoch(): number {
    return this.currentEpoch;
  }

  /** `true` while a rekey overlap window is still open. */
  get hasPendingOldEpoch(): boolean {
    return this.pendingOldEpoch !== undefined;
  }

  /**
   * Rotate the X-Wing session: fresh encapsulation against the same recipient,
   * `epoch += 1`, and the previous shared secret moves to the overlap slot so
   * {@link WarrenPqClientSession.openResponse} can still decode in-flight
   * old-epoch reverse frames. Returns the new `(encapsulatedKey, pqCt)`.
   */
  rekey(): { encapsulatedKey: Uint8Array; pqCt: Uint8Array } {
    const enc = xwingEncapsulateRandom(this.recipient);
    this.pendingOldEpoch = { sharedSecret: this.sharedSecret, epoch: this.currentEpoch };
    this.sharedSecret = enc.sharedSecret;
    this.currentEncapsulatedKey = enc.ciphertext.x25519Ct;
    this.currentPqCt = enc.ciphertext.mlkemCt;
    this.currentEpoch += 1;
    return { encapsulatedKey: this.currentEncapsulatedKey, pqCt: this.currentPqCt };
  }

  /** End the rekey overlap window. */
  prunePendingOldEpoch(): void {
    this.pendingOldEpoch = undefined;
  }

  /**
   * Seal `payload` into a `/v2` SETUP / rekey frame: `pq_ct` carries the ML-KEM
   * ciphertext so the exit can establish the epoch session.
   */
  sealSetup(payload: Uint8Array, epoch: number, seq: bigint): WarrenMultihopFrameV2 {
    return this.sealInner(payload, epoch, seq, this.currentPqCt);
  }

  /**
   * Seal `payload` into a `/v2` steady-state DATA frame with an EMPTY `pq_ct`:
   * the exit already holds this epoch's session, so the 1088-byte ML-KEM
   * ciphertext is not re-sent per datagram. Reusing an `(epoch, seq)` pair reuses
   * the per-packet key under a zero nonce and is a nonce-reuse break, so callers
   * MUST NOT repeat one.
   */
  seal(payload: Uint8Array, epoch: number, seq: bigint): WarrenMultihopFrameV2 {
    return this.sealInner(payload, epoch, seq, new Uint8Array(0));
  }

  private sealInner(
    payload: Uint8Array,
    epoch: number,
    seq: bigint,
    pqCt: Uint8Array,
  ): WarrenMultihopFrameV2 {
    const key = derivePerPacketKey(this.sharedSecret, composeExportInfo(epoch, seq));
    const aad = composeAad(this.exitId, epoch, seq);
    const sealed = chacha20poly1305(key, NONCE_ZERO_12, aad).encrypt(payload);
    const ciphertext = sealed.subarray(0, sealed.length - AEAD_TAG_LEN);
    const aeadTag = sealed.subarray(sealed.length - AEAD_TAG_LEN);
    return {
      version: WARREN_HPKE_VERSION_V2,
      exitId: this.exitId,
      epoch,
      seq,
      encapsulatedKey: this.currentEncapsulatedKey,
      pqCt,
      aeadTag,
      ciphertext,
    };
  }

  /**
   * Open a reverse-direction (exit -> client) `/v2` frame, returning the
   * recovered plaintext. Uses this epoch's shared secret, or the pending
   * old-epoch secret during a rekey overlap window.
   *
   * @throws Error if the frame targets a different exit, has the wrong version,
   * or the AEAD tag does not verify (tamper, cross-direction, or unknown epoch).
   */
  openResponse(frame: WarrenMultihopFrameV2): Uint8Array {
    if (!sameExit(frame.exitId, this.exitId)) {
      throw new Error('reverse frame targets a different exit');
    }
    if (frame.version !== WARREN_HPKE_VERSION_V2) {
      throw new Error(`unsupported /v2 frame version ${frame.version}`);
    }
    let sharedSecret: Uint8Array;
    if (frame.epoch === this.currentEpoch) {
      sharedSecret = this.sharedSecret;
    } else if (this.pendingOldEpoch !== undefined && this.pendingOldEpoch.epoch === frame.epoch) {
      sharedSecret = this.pendingOldEpoch.sharedSecret;
    } else {
      throw new Error('no session key for the frame epoch');
    }
    return openWithSecret(sharedSecret, this.exitId, frame, true);
  }
}

/**
 * Receiver (exit) side of a `/v2` post-quantum multihop session. Mirrors the
 * Rust `PqExitSession`. Included for cross-implementation seal round-trips
 * (a browser client is normally only the sender).
 */
export class WarrenPqExitSession {
  private constructor(
    private readonly sharedSecret: Uint8Array,
    readonly exitId: Uint8Array,
    private readonly encapsulatedKey: Uint8Array,
  ) {}

  /**
   * Set up a PQ receiver session by X-Wing-decapsulating the client's setup
   * frame material (`encapsulatedKey` = `ct_X`, `pqCt` = `ct_M`) with the exit's
   * X-Wing recipient secret key.
   */
  static create(
    secret: XWingRecipientSecretKey,
    encapsulatedKey: Uint8Array,
    pqCt: Uint8Array,
    exitId: Uint8Array,
  ): WarrenPqExitSession {
    const sharedSecret = xwingDecapsulate(secret, { mlkemCt: pqCt, x25519Ct: encapsulatedKey });
    return new WarrenPqExitSession(sharedSecret, exitId, encapsulatedKey);
  }

  /**
   * Open a forward-direction (client -> exit) `/v2` frame.
   *
   * @throws Error if the frame targets a different exit, has the wrong version,
   * or the AEAD tag does not verify.
   */
  open(frame: WarrenMultihopFrameV2): Uint8Array {
    if (!sameExit(frame.exitId, this.exitId)) {
      throw new Error('frame targets a different exit');
    }
    if (frame.version !== WARREN_HPKE_VERSION_V2) {
      throw new Error(`unsupported /v2 frame version ${frame.version}`);
    }
    return openWithSecret(this.sharedSecret, this.exitId, frame, false);
  }

  /**
   * Seal a reverse-direction (exit -> client) `/v2` frame. Steady-state: `pq_ct`
   * is empty (the client already holds this epoch's session) and the
   * `encapsulated_key` (`ct_X`) is echoed so the reverse wire shape matches the
   * forward one.
   */
  sealResponse(payload: Uint8Array, epoch: number, seq: bigint): WarrenMultihopFrameV2 {
    const key = derivePerPacketKey(this.sharedSecret, composeExportInfoReverse(epoch, seq));
    const aad = composeAad(this.exitId, epoch, seq);
    const sealed = chacha20poly1305(key, NONCE_ZERO_12, aad).encrypt(payload);
    const ciphertext = sealed.subarray(0, sealed.length - AEAD_TAG_LEN);
    const aeadTag = sealed.subarray(sealed.length - AEAD_TAG_LEN);
    return {
      version: WARREN_HPKE_VERSION_V2,
      exitId: this.exitId,
      epoch,
      seq,
      encapsulatedKey: this.encapsulatedKey,
      pqCt: new Uint8Array(0),
      aeadTag,
      ciphertext,
    };
  }
}

/** Shared open path. `reverse = true` uses the reverse direction tag (a client
 * opening an exit reply); `reverse = false` the forward info (an exit opening a
 * client frame). */
function openWithSecret(
  sharedSecret: Uint8Array,
  exitId: Uint8Array,
  frame: WarrenMultihopFrameV2,
  reverse: boolean,
): Uint8Array {
  const info = reverse
    ? composeExportInfoReverse(frame.epoch, frame.seq)
    : composeExportInfo(frame.epoch, frame.seq);
  const key = derivePerPacketKey(sharedSecret, info);
  const aad = composeAad(exitId, frame.epoch, frame.seq);
  const sealed = new Uint8Array(frame.ciphertext.length + AEAD_TAG_LEN);
  sealed.set(frame.ciphertext, 0);
  sealed.set(frame.aeadTag, frame.ciphertext.length);
  return chacha20poly1305(key, NONCE_ZERO_12, aad).decrypt(sealed);
}
