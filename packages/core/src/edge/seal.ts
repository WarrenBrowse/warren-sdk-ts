/**
 * The client side of the Warren multi-hop seal: turn a plaintext payload into a
 * {@link WarrenMultihopFrame} an exit can HPKE-open, byte-for-byte compatible
 * with the Rust `warrenguard-multihop` `ClientSession::seal`.
 *
 * Per RFC-9180-hold-then-export: the HPKE KEM/setup runs once per session
 * ({@link WarrenClientSession.create}); every packet then derives a fresh
 * per-packet ChaCha20-Poly1305 key via HPKE secret-export keyed on
 * `(epoch, seq)`, and encrypts under a FIXED all-zero nonce. The zero nonce is
 * safe only because the key is unique per `(epoch, seq)`.
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { WARREN_HPKE_VERSION, type WarrenMultihopFrame, encodeMultihopFrame } from './frame.js';
import { type HpkeSender, exportSecret, setupBaseSender } from './hpke.js';

/** HPKE key-schedule `info`; must equal the Rust `WARREN_HPKE_INFO_V1`. */
const WARREN_HPKE_INFO_V1 = new TextEncoder().encode('warren/multihop/v1/hpke-info');
/** Prefix of BOTH the AEAD AAD and the per-packet export info; must equal the
 * Rust `WARREN_HPKE_AAD_V1`. */
const WARREN_HPKE_AAD_V1 = new TextEncoder().encode('warren/multihop/v1/aad');

const PER_PACKET_KEY_LEN = 32;
const NONCE_ZERO_12 = new Uint8Array(12);
const AEAD_TAG_LEN = 16;
const EXIT_ID_LEN = 16;
/** Trailing byte on the reverse (exit -> client) export info; must equal the
 * Rust `DIRECTION_TAG_REVERSE`. Keeps forward and reverse per-packet keys
 * distinct even when `(epoch, seq)` repeat across directions. */
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

/**
 * Per-packet HPKE export `info`: `WARREN_HPKE_AAD_V1 || epoch_be32 || seq_be64`
 * (34 bytes). Note it reuses the AAD prefix, not the HPKE key-schedule prefix,
 * and carries no exit_id (exit_id lives only in the AAD).
 */
function composeExportInfo(epoch: number, seq: bigint): Uint8Array {
  const out = new Uint8Array(WARREN_HPKE_AAD_V1.length + 4 + 8);
  out.set(WARREN_HPKE_AAD_V1, 0);
  out.set(beU32(epoch), WARREN_HPKE_AAD_V1.length);
  out.set(beU64(seq), WARREN_HPKE_AAD_V1.length + 4);
  return out;
}

/**
 * Reverse-direction (exit -> client) export info: the forward info plus a
 * trailing {@link DIRECTION_TAG_REVERSE} byte (35 bytes). Used to open the
 * frames an exit seals back to the client.
 */
function composeExportInfoReverse(epoch: number, seq: bigint): Uint8Array {
  const fwd = composeExportInfo(epoch, seq);
  const out = new Uint8Array(fwd.length + 1);
  out.set(fwd, 0);
  out[fwd.length] = DIRECTION_TAG_REVERSE;
  return out;
}

/**
 * AEAD AAD: `WARREN_HPKE_AAD_V1 || exit_id(16) || epoch_be32 || seq_be64`
 * (50 bytes). Binds the ciphertext to its exit and its `(epoch, seq)` slot.
 */
function composeAad(exitId: Uint8Array, epoch: number, seq: bigint): Uint8Array {
  const out = new Uint8Array(WARREN_HPKE_AAD_V1.length + EXIT_ID_LEN + 4 + 8);
  let o = 0;
  out.set(WARREN_HPKE_AAD_V1, o);
  o += WARREN_HPKE_AAD_V1.length;
  out.set(exitId, o);
  o += EXIT_ID_LEN;
  out.set(beU32(epoch), o);
  o += 4;
  out.set(beU64(seq), o);
  return out;
}

/**
 * A sender session bound to one exit. Holds the HPKE exporter secret and the
 * encapsulated key that every frame of the session carries.
 */
export class WarrenClientSession {
  private constructor(
    private readonly sender: HpkeSender,
    /** The 16-byte exit routing tag. */
    readonly exitId: Uint8Array,
  ) {
    if (exitId.length !== EXIT_ID_LEN) {
      throw new RangeError(`exitId must be ${EXIT_ID_LEN} bytes`);
    }
  }

  /**
   * Set up a session against an exit's long-lived X25519 public key
   * (`exitX25519Pubkey`, 32 bytes; the `exitX25519PubkeyHex` from a verified
   * multi-hop directory). `ephemeralPriv` is for deterministic test vectors
   * only; production omits it.
   */
  static create(
    exitX25519Pubkey: Uint8Array,
    exitId: Uint8Array,
    ephemeralPriv?: Uint8Array,
  ): WarrenClientSession {
    const sender = setupBaseSender(exitX25519Pubkey, WARREN_HPKE_INFO_V1, ephemeralPriv);
    return new WarrenClientSession(sender, exitId);
  }

  /** The 32-byte ephemeral X25519 public key carried on every frame. */
  get encapsulatedKey(): Uint8Array {
    return this.sender.enc;
  }

  /**
   * Seal `payload` into a {@link WarrenMultihopFrame} for `(epoch, seq)`. The
   * caller supplies a per-session-monotonic `seq`; reusing an `(epoch, seq)`
   * pair reuses the per-packet key under a zero nonce and is a nonce-reuse
   * break, so callers MUST NOT repeat one.
   */
  seal(payload: Uint8Array, epoch: number, seq: bigint): WarrenMultihopFrame {
    const key = exportSecret(
      this.sender.exporterSecret,
      composeExportInfo(epoch, seq),
      PER_PACKET_KEY_LEN,
    );
    const aad = composeAad(this.exitId, epoch, seq);
    const sealed = chacha20poly1305(key, NONCE_ZERO_12, aad).encrypt(payload);
    // noble returns ciphertext || tag; the wire frame stores them detached.
    const ciphertext = sealed.subarray(0, sealed.length - AEAD_TAG_LEN);
    const aeadTag = sealed.subarray(sealed.length - AEAD_TAG_LEN);
    return {
      version: WARREN_HPKE_VERSION,
      exitId: this.exitId,
      epoch,
      seq,
      encapsulatedKey: this.sender.enc,
      aeadTag,
      ciphertext,
    };
  }

  /** Seal and immediately postcard-encode, the bytes to put on the wire. */
  sealFrameBytes(payload: Uint8Array, epoch: number, seq: bigint): Uint8Array {
    return encodeMultihopFrame(this.seal(payload, epoch, seq));
  }

  /**
   * Open a reverse-direction frame the exit sealed back to this client
   * (`exit -> client`), returning the recovered plaintext. Uses the session's
   * shared HPKE exporter secret with the reverse export info; the AAD is bound
   * to the frame's own exit_id/epoch/seq exactly as the forward direction.
   *
   * @throws Error if the frame targets a different exit or the AEAD tag does not
   * verify (tampered ciphertext, AAD, or tag).
   */
  openResponse(frame: WarrenMultihopFrame): Uint8Array {
    if (
      frame.exitId.length !== this.exitId.length ||
      !frame.exitId.every((b, i) => b === this.exitId[i])
    ) {
      throw new Error('reverse frame targets a different exit');
    }
    const key = exportSecret(
      this.sender.exporterSecret,
      composeExportInfoReverse(frame.epoch, frame.seq),
      PER_PACKET_KEY_LEN,
    );
    const aad = composeAad(this.exitId, frame.epoch, frame.seq);
    const sealed = new Uint8Array(frame.ciphertext.length + AEAD_TAG_LEN);
    sealed.set(frame.ciphertext, 0);
    sealed.set(frame.aeadTag, frame.ciphertext.length);
    return chacha20poly1305(key, NONCE_ZERO_12, aad).decrypt(sealed);
  }
}
