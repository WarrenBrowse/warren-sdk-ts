/**
 * X-Wing hybrid KEM: X25519 + ML-KEM-768 (draft-connolly-cfrg-xwing-kem), the
 * security-critical combiner for the Warren `/v2` post-quantum multihop seal.
 * Byte-for-byte compatible with the Rust `warrenguard-multihop` `xwing.rs`, and
 * pinned by the official draft KATs (`vectors/xwing_kem.json`).
 *
 * This is the exact X-Wing construction, NOT a naive XOR of the two component
 * shared secrets. The hybrid secret is
 *
 *   ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
 *
 * where `ss_M` is the ML-KEM-768 shared secret, `ss_X` the X25519 raw DH output,
 * `ct_X` the X25519 ephemeral public (the "X25519 ciphertext"), `pk_X` the
 * recipient's static X25519 public, and `XWingLabel` the 6-byte tag `\.//^\`
 * hashed LAST. The X-Wing ciphertext is `ct_M (1088) || ct_X (32)`.
 *
 * Deployment note: X-Wing's native keygen derives both component keys from one
 * 32-byte seed via `expandDecapsulationKey`. Warren instead uses INDEPENDENTLY
 * generated component keys (the exit's long-lived X25519 key + a separate
 * ML-KEM-768 key). Only the combiner and the KEM operations are shared with
 * X-Wing; the single-seed keygen is a storage convenience the protocol does not
 * need, and its security argument reduces to the combiner. {@link xwingReferenceFlow}
 * still replays the official single-seed vectors end-to-end through the exact
 * same combiner + ML-KEM + X25519 code the protocol uses.
 *
 * Secrets (shared secrets, X25519 scalars, ML-KEM decapsulation keys) are raw
 * `Uint8Array`s; JavaScript cannot reliably zeroize, so callers MUST keep them
 * out of logs and drop references promptly. No secret is ever put in an Error.
 */

import { x25519 } from '@noble/curves/ed25519';
import { sha3_256, shake256 } from '@noble/hashes/sha3';
import { concatBytes } from '@noble/hashes/utils';
import { ml_kem768 } from '@noble/post-quantum/ml-kem';

/** The 6-byte X-Wing domain-separation label `\.//^\`, hashed LAST in the
 * combiner (draft-connolly-cfrg-xwing-kem). Frozen. */
export const XWING_LABEL = new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);

/** ML-KEM-768 encapsulation-key (recipient public key) length in bytes. */
export const XWING_MLKEM_EK_LEN = 1184;
/** ML-KEM-768 ciphertext length in bytes. */
export const XWING_MLKEM_CT_LEN = 1088;
/** X25519 public-key / ciphertext / shared-secret length in bytes. */
export const XWING_X25519_LEN = 32;
/** Full X-Wing ciphertext length: `ct_M (1088) || ct_X (32)`. */
export const XWING_CT_LEN = XWING_MLKEM_CT_LEN + XWING_X25519_LEN;

/** The recipient (exit) X-Wing public key: an ML-KEM-768 encapsulation key plus
 * the static X25519 public key. Built by the client from the exit's SIGNED
 * descriptor before sealing. */
export interface XWingRecipientPublicKey {
  /** ML-KEM-768 encapsulation key (`ek_M`, 1184 bytes). */
  mlkem768Ek: Uint8Array;
  /** Static X25519 recipient public (`pk_X`, 32 bytes), bound into the combiner. */
  x25519Pubkey: Uint8Array;
}

/** The recipient (exit) X-Wing secret key: an ML-KEM-768 decapsulation key plus
 * the static X25519 secret. The X25519 public is recomputed from the scalar so
 * the combiner always binds a `pk_X` consistent with `sk_X`. */
export interface XWingRecipientSecretKey {
  /** ML-KEM-768 decapsulation key bytes. */
  mlkem768Dk: Uint8Array;
  /** Raw X25519 secret scalar (`sk_X`, 32 bytes). */
  x25519Secret: Uint8Array;
  /** X25519 public recomputed from the scalar (`pk_X`, 32 bytes). */
  x25519Pubkey: Uint8Array;
}

/** The X-Wing hybrid ciphertext, carried on the wire as two `/v2` frame fields:
 * `mlkemCt` in `pq_ct`, `x25519Ct` in the classical `encapsulated_key`. */
export interface XWingCiphertext {
  /** ML-KEM-768 ciphertext half (`ct_M`, 1088 bytes). */
  mlkemCt: Uint8Array;
  /** X25519 ephemeral public half (`ct_X`, 32 bytes). */
  x25519Ct: Uint8Array;
}

/** An X-Wing encapsulation: the hybrid ciphertext and the sender's copy of the
 * hybrid shared secret. */
export interface XWingEncapsulation {
  ciphertext: XWingCiphertext;
  /** 32-byte hybrid shared secret; feed to the `/v2` HKDF key schedule only. */
  sharedSecret: Uint8Array;
}

function expectLen(bytes: Uint8Array, len: number, field: string): void {
  if (bytes.length !== len) {
    throw new RangeError(`${field} must be ${len} bytes, got ${bytes.length}`);
  }
}

/**
 * The X-Wing hybrid combiner `SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)`.
 *
 * The ONLY correct way to combine the two component secrets: a XOR or a plain
 * concatenation-without-the-transcript would drop the binding to `ct_X` / `pk_X`
 * and break the hybrid IND-CCA argument. The label is hashed last, matching
 * draft-connolly-cfrg-xwing-kem and the deployed RustCrypto `x-wing` crate.
 */
export function xwingCombiner(
  ssM: Uint8Array,
  ssX: Uint8Array,
  ctX: Uint8Array,
  pkX: Uint8Array,
): Uint8Array {
  return sha3_256(concatBytes(ssM, ssX, ctX, pkX, XWING_LABEL));
}

/** Reassemble a recipient public key from the exit's descriptor material: the
 * raw ML-KEM-768 encapsulation key (1184 bytes) and the static X25519 public
 * (32 bytes). Mirrors `XWingRecipientPublicKey::from_descriptor_bytes`. */
export function xwingRecipientPublicFromDescriptor(
  mlkem768Ek: Uint8Array,
  x25519Pubkey: Uint8Array,
): XWingRecipientPublicKey {
  expectLen(mlkem768Ek, XWING_MLKEM_EK_LEN, 'mlkem768Ek');
  expectLen(x25519Pubkey, XWING_X25519_LEN, 'x25519Pubkey');
  return { mlkem768Ek, x25519Pubkey };
}

/** Assemble a recipient secret key from an ML-KEM-768 decapsulation key and a
 * raw X25519 secret scalar; the X25519 public is recomputed. Mirrors
 * `XWingRecipientSecretKey::from_parts`. */
export function xwingRecipientFromParts(
  mlkem768Dk: Uint8Array,
  x25519Secret: Uint8Array,
): XWingRecipientSecretKey {
  expectLen(x25519Secret, XWING_X25519_LEN, 'x25519Secret');
  return {
    mlkem768Dk,
    x25519Secret,
    x25519Pubkey: x25519.getPublicKey(x25519Secret),
  };
}

/** A recipient keypair (secret + public), the way both a fresh keygen and the
 * deterministic derivations return it. */
export interface XWingRecipientKeypair {
  secretKey: XWingRecipientSecretKey;
  publicKey: XWingRecipientPublicKey;
}

/**
 * Deterministically derive a recipient keypair from INDEPENDENT component seeds:
 * ML-KEM keygen uses `(d, z)`, the X25519 scalar is `skxSeed`. This is the shape
 * Warren actually deploys (independent keys, not X-Wing's single seed), and the
 * `pq_hpke_seal_v2.json` recipient. Mirrors
 * `XWingRecipientSecretKey::derive_deterministic`.
 */
export function xwingRecipientFromComponentSeeds(
  d: Uint8Array,
  z: Uint8Array,
  skxSeed: Uint8Array,
): XWingRecipientKeypair {
  expectLen(d, 32, 'd');
  expectLen(z, 32, 'z');
  expectLen(skxSeed, XWING_X25519_LEN, 'skxSeed');
  // noble ml_kem768.keygen takes a 64-byte seed = d || z (FIPS 203 KeyGen_internal).
  const kp = ml_kem768.keygen(concatBytes(d, z));
  const secretKey = xwingRecipientFromParts(kp.secretKey, skxSeed);
  return {
    secretKey,
    publicKey: { mlkem768Ek: kp.publicKey, x25519Pubkey: secretKey.x25519Pubkey },
  };
}

/**
 * Derive a recipient keypair from an X-Wing native 32-byte seed via
 * `expandDecapsulationKey` (draft-connolly-cfrg-xwing-kem): `SHAKE256(seed, 96)`
 * splits into the ML-KEM `(d, z)` and the X25519 scalar. Used ONLY to replay the
 * official single-seed KATs through the exact same combiner + KEM code the
 * protocol uses; Warren itself uses {@link xwingRecipientFromParts}.
 */
export function xwingRecipientFromXwingSeed(seed: Uint8Array): XWingRecipientKeypair {
  expectLen(seed, 32, 'seed');
  const expanded = shake256(seed, { dkLen: 96 });
  const d = expanded.subarray(0, 32);
  const z = expanded.subarray(32, 64);
  const skx = expanded.subarray(64, 96);
  return xwingRecipientFromComponentSeeds(d, z, skx);
}

/**
 * X-Wing encapsulation with the exact ML-KEM message randomness (`mSeed`) and
 * X25519 ephemeral scalar (`ephXSeed`). Both MUST be freshly drawn from a CSPRNG
 * by the caller in production (the session layer draws them); this deterministic
 * form exists for golden vectors. Mirrors `xwing_encapsulate`.
 */
export function xwingEncapsulate(
  recipient: XWingRecipientPublicKey,
  mSeed: Uint8Array,
  ephXSeed: Uint8Array,
): XWingEncapsulation {
  expectLen(mSeed, 32, 'mSeed');
  expectLen(ephXSeed, XWING_X25519_LEN, 'ephXSeed');
  const { cipherText: mlkemCt, sharedSecret: ssM } = ml_kem768.encapsulate(
    recipient.mlkem768Ek,
    mSeed,
  );
  const ctX = x25519.getPublicKey(ephXSeed);
  const ssX = x25519.getSharedSecret(ephXSeed, recipient.x25519Pubkey);
  const sharedSecret = xwingCombiner(ssM, ssX, ctX, recipient.x25519Pubkey);
  return { ciphertext: { mlkemCt, x25519Ct: ctX }, sharedSecret };
}

/**
 * X-Wing encapsulation drawing fresh randomness from the platform CSPRNG (the
 * production path). Returns the hybrid ciphertext and the sender's shared secret.
 */
export function xwingEncapsulateRandom(recipient: XWingRecipientPublicKey): XWingEncapsulation {
  const mSeed = crypto.getRandomValues(new Uint8Array(32));
  const ephXSeed = x25519.utils.randomPrivateKey();
  return xwingEncapsulate(recipient, mSeed, ephXSeed);
}

/**
 * X-Wing decapsulation: recover the same hybrid shared secret the sender derived.
 * ML-KEM decapsulation is implicit-reject (a tampered `ct_M` yields a different,
 * pseudo-random `ss_M` rather than an error), so the returned secret simply will
 * not match the sender's on tamper. Mirrors `xwing_decapsulate`.
 */
export function xwingDecapsulate(
  secret: XWingRecipientSecretKey,
  ciphertext: XWingCiphertext,
): Uint8Array {
  expectLen(ciphertext.mlkemCt, XWING_MLKEM_CT_LEN, 'mlkemCt');
  expectLen(ciphertext.x25519Ct, XWING_X25519_LEN, 'x25519Ct');
  const ssM = ml_kem768.decapsulate(ciphertext.mlkemCt, secret.mlkem768Dk);
  const ssX = x25519.getSharedSecret(secret.x25519Secret, ciphertext.x25519Ct);
  return xwingCombiner(ssM, ssX, ciphertext.x25519Ct, secret.x25519Pubkey);
}

/** Intermediate + final values of an end-to-end X-Wing flow, produced by
 * {@link xwingReferenceFlow} for the KAT. */
export interface XWingReferenceOutput {
  /** X-Wing public key `ek_M || pk_X` (1216 bytes). */
  publicKey: Uint8Array;
  /** X-Wing ciphertext `ct_M || ct_X` (1120 bytes). */
  ciphertext: Uint8Array;
  /** Shared secret computed by encapsulation. */
  sharedSecretEncaps: Uint8Array;
  /** Shared secret recovered by decapsulation (must equal the encaps one). */
  sharedSecretDecaps: Uint8Array;
}

/**
 * Run the full X-Wing native flow (single-seed keygen -> derandomized encaps ->
 * decaps) through the PRODUCTION combiner + KEM code, so the KAT can assert
 * against the official draft vectors. `seed` is the 32-byte X-Wing secret seed;
 * `eseed` is the 64-byte encapsulation randomness (`eseed[0..32]` = ML-KEM
 * message, `eseed[32..64]` = X25519 ephemeral scalar). Mirrors
 * `xwing_reference_flow`.
 */
export function xwingReferenceFlow(seed: Uint8Array, eseed: Uint8Array): XWingReferenceOutput {
  expectLen(seed, 32, 'seed');
  expectLen(eseed, 64, 'eseed');
  const { secretKey, publicKey } = xwingRecipientFromXwingSeed(seed);
  const enc = xwingEncapsulate(publicKey, eseed.subarray(0, 32), eseed.subarray(32, 64));
  const ssDec = xwingDecapsulate(secretKey, enc.ciphertext);
  return {
    publicKey: concatBytes(publicKey.mlkem768Ek, publicKey.x25519Pubkey),
    ciphertext: concatBytes(enc.ciphertext.mlkemCt, enc.ciphertext.x25519Ct),
    sharedSecretEncaps: enc.sharedSecret,
    sharedSecretDecaps: ssDec,
  };
}
