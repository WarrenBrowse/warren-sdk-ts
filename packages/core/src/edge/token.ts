/**
 * Privacy Pass publicly-verifiable blind-RSA tokens (RFC 9578 token type
 * `0x0002`), the anonymous v7 session-token subscription proof a Warren exit
 * verifies OFFLINE and spends. This is the client half of RFC 9474 RSABSSA in
 * the `RSABSSA-SHA384-PSS-Deterministic` variant (2048-bit modulus), matching
 * the Rust `warrenguard-token` crate byte-for-byte: a token produced here
 * verifies under `IssuerPublicKey::verify_token`.
 *
 * The client {@link blindToken}s a token pre-image, sends the blinded request to
 * the issuer, and {@link finalizeToken}s the returned blind signature into a
 * {@link Token} whose 256-byte authenticator is a plain RSASSA-PSS signature
 * (the blinding cancels). No RSA library is used: the modular arithmetic is
 * bigint, PSS uses `@noble/hashes` SHA-384.
 */

import { sha256 } from '@noble/hashes/sha2';
import { sha384 } from '@noble/hashes/sha512';
import { WarrenEdgeError } from './errors.js';
import type { TokenRandom } from './token-blinding.js';

/** Privacy Pass blind-RSA token type (RFC 9578 section 8.2.1). */
export const TOKEN_TYPE_BLIND_RSA = 0x0002;
const NONCE_LEN = 32;
const CHALLENGE_DIGEST_LEN = 32;
const TOKEN_KEY_ID_LEN = 32;
/** RSASSA-PSS signature / modulus length in bytes (2048-bit). */
export const AUTHENTICATOR_LEN = 256;
/** Full serialized token length (RFC 9577 section 2.2). */
export const TOKEN_LEN =
  2 + NONCE_LEN + CHALLENGE_DIGEST_LEN + TOKEN_KEY_ID_LEN + AUTHENTICATOR_LEN;

const MOD_BITS = 2048;
const HASH_LEN = 48; // SHA-384

// ---- bigint / octet-string helpers ----------------------------------------

function os2ip(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) {
    n = (n << 8n) | BigInt(b);
  }
  return n;
}

function i2osp(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let v = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw new RangeError('integer too large for the requested octet length');
  }
  return out;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % mod;
    }
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [((a % m) + m) % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) {
    throw new Error('no modular inverse (value not coprime to modulus)');
  }
  return ((old_s % m) + m) % m;
}

// ---- MGF1 + EMSA-PSS (RFC 8017) with SHA-384, salt length 48 --------------

function mgf1Sha384(seed: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let counter = 0;
  let offset = 0;
  while (offset < length) {
    const c = new Uint8Array(4);
    new DataView(c.buffer).setUint32(0, counter, false);
    const block = sha384.create().update(seed).update(c).digest();
    const take = Math.min(block.length, length - offset);
    out.set(block.subarray(0, take), offset);
    offset += take;
    counter += 1;
  }
  return out;
}

/** EMSA-PSS-ENCODE (RFC 8017 section 9.1.1) with SHA-384 and salt length 48
 * (`= hLen`, the RSABSSA `PSS` mode). `salt` is client-chosen (random in
 * production); the RSABSSA "Deterministic" label refers only to the absence of a
 * message randomizer, not the salt. Returns the `emLen`-byte encoded message. */
function emsaPssEncode(message: Uint8Array, emBits: number, salt: Uint8Array): Uint8Array {
  const emLen = Math.ceil(emBits / 8);
  const sLen = salt.length;
  const mHash = sha384(message);
  if (emLen < HASH_LEN + sLen + 2) {
    throw new Error('encoding error: emLen too small');
  }
  // M' = (0x00 * 8) || mHash || salt.
  const mPrime = new Uint8Array(8 + HASH_LEN + sLen);
  mPrime.set(mHash, 8);
  mPrime.set(salt, 8 + HASH_LEN);
  const h = sha384(mPrime);
  // DB = PS(0x00...) || 0x01 || salt.
  const dbLen = emLen - HASH_LEN - 1;
  const db = new Uint8Array(dbLen);
  db[dbLen - sLen - 1] = 0x01;
  db.set(salt, dbLen - sLen);
  const dbMask = mgf1Sha384(h, dbLen);
  const maskedDb = new Uint8Array(dbLen);
  for (let i = 0; i < dbLen; i++) {
    maskedDb[i] = (db[i] ?? 0) ^ (dbMask[i] ?? 0);
  }
  // Clear the leftmost 8*emLen - emBits bits of maskedDB.
  const clearBits = 8 * emLen - emBits;
  maskedDb[0] = (maskedDb[0] ?? 0) & (0xff >> clearBits);
  const em = new Uint8Array(emLen);
  em.set(maskedDb, 0);
  em.set(h, dbLen);
  em[emLen - 1] = 0xbc;
  return em;
}

/** EMSA-PSS-VERIFY (RFC 8017 section 9.1.2), SHA-384, salt length 48. */
function emsaPssVerify(message: Uint8Array, em: Uint8Array, emBits: number): boolean {
  const emLen = Math.ceil(emBits / 8);
  const sLen = HASH_LEN;
  const mHash = sha384(message);
  if (emLen < HASH_LEN + sLen + 2) {
    return false;
  }
  if (em[emLen - 1] !== 0xbc) {
    return false;
  }
  const dbLen = emLen - HASH_LEN - 1;
  const maskedDb = em.subarray(0, dbLen);
  const h = em.subarray(dbLen, dbLen + HASH_LEN);
  const clearBits = 8 * emLen - emBits;
  if (((maskedDb[0] ?? 0) & ((0xff << (8 - clearBits)) & 0xff)) !== 0) {
    return false;
  }
  const dbMask = mgf1Sha384(h, dbLen);
  const db = new Uint8Array(dbLen);
  for (let i = 0; i < dbLen; i++) {
    db[i] = (maskedDb[i] ?? 0) ^ (dbMask[i] ?? 0);
  }
  db[0] = (db[0] ?? 0) & (0xff >> clearBits);
  for (let i = 0; i < dbLen - sLen - 1; i++) {
    if (db[i] !== 0x00) {
      return false;
    }
  }
  if (db[dbLen - sLen - 1] !== 0x01) {
    return false;
  }
  const salt = db.subarray(dbLen - sLen);
  const mPrime = new Uint8Array(8 + HASH_LEN + sLen);
  mPrime.set(mHash, 8);
  mPrime.set(salt, 8 + HASH_LEN);
  const hPrime = sha384(mPrime);
  return hPrime.every((b, i) => b === h[i]);
}

// ---- issuer public key + token client -------------------------------------

/** An RSASSA-PSS issuer public key: the modulus/exponent and the RFC 9578
 * key id (`SHA-256(SubjectPublicKeyInfo)`). */
export interface IssuerPublicKey {
  n: bigint;
  e: bigint;
  /** `SHA-256(spki)`, the 32-byte `token_key_id` every token carries. */
  keyId: Uint8Array;
}

/**
 * Builds an {@link IssuerPublicKey} from the raw modulus `n`, exponent `e`
 * (both big-endian bytes), and the issuer's `SubjectPublicKeyInfo` DER (whose
 * SHA-256 is the key id). This is what a client derives from the token
 * directory the account API publishes.
 */
export function issuerPublicKey(n: Uint8Array, e: Uint8Array, spki: Uint8Array): IssuerPublicKey {
  return { n: os2ip(n), e: os2ip(e), keyId: sha256(spki) };
}

/** Reads one DER TLV at `offset`, returning the tag, the value byte range, and
 * the offset just past the value. */
function readTlv(der: Uint8Array, offset: number): { tag: number; start: number; end: number } {
  const tag = der[offset] ?? 0;
  let o = offset + 1;
  let len = der[o] ?? 0;
  o += 1;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) {
      len = (len << 8) | (der[o] ?? 0);
      o += 1;
    }
  }
  return { tag, start: o, end: o + len };
}

/**
 * Builds an {@link IssuerPublicKey} from an RSASSA-PSS `SubjectPublicKeyInfo`
 * DER (the `spki_b64` a token directory publishes): parses the modulus and
 * exponent out of the DER and takes the key id as `SHA-256(spki)`. Structure:
 * `SEQ { AlgorithmIdentifier, BIT STRING { 0x00, SEQ { INTEGER n, INTEGER e } } }`.
 */
export function issuerPublicKeyFromSpki(spki: Uint8Array): IssuerPublicKey {
  const outer = readTlv(spki, 0); // outer SEQUENCE
  const algId = readTlv(spki, outer.start); // AlgorithmIdentifier SEQUENCE
  const bitString = readTlv(spki, algId.end); // BIT STRING
  if (bitString.tag !== 0x03) {
    throw new WarrenEdgeError('token_issuer', 'SPKI: expected a BIT STRING for the public key');
  }
  // BIT STRING content is 0x00 (unused bits) then the RSAPublicKey DER.
  const rsaSeq = readTlv(spki, bitString.start + 1);
  const nTlv = readTlv(spki, rsaSeq.start);
  const eTlv = readTlv(spki, nTlv.end);
  const strip = (a: Uint8Array) => (a.length > 1 && a[0] === 0x00 ? a.subarray(1) : a);
  const n = strip(spki.subarray(nTlv.start, nTlv.end));
  const e = strip(spki.subarray(eTlv.start, eTlv.end));
  return { n: os2ip(n), e: os2ip(e), keyId: sha256(spki) };
}

/**
 * Serializes a `TokenChallenge` (RFC 9577 section 2.1):
 * `token_type(2) || issuer_name<u16> || redemption_context<u8> ||
 * origin_info<u16>`. `redemptionContext` must be empty or exactly 32 bytes.
 */
export function serializeTokenChallenge(params: {
  issuerName: string;
  redemptionContext?: Uint8Array;
  originInfo?: Uint8Array;
}): Uint8Array {
  const issuerName = new TextEncoder().encode(params.issuerName);
  const rc = params.redemptionContext ?? new Uint8Array(0);
  const oi = params.originInfo ?? new Uint8Array(0);
  if (rc.length !== 0 && rc.length !== 32) {
    throw new RangeError('redemption_context must be empty or exactly 32 bytes');
  }
  const out = new Uint8Array(2 + 2 + issuerName.length + 1 + rc.length + 2 + oi.length);
  const dv = new DataView(out.buffer);
  let o = 0;
  dv.setUint16(o, TOKEN_TYPE_BLIND_RSA, false);
  o += 2;
  dv.setUint16(o, issuerName.length, false);
  o += 2;
  out.set(issuerName, o);
  o += issuerName.length;
  out[o++] = rc.length;
  out.set(rc, o);
  o += rc.length;
  dv.setUint16(o, oi.length, false);
  o += 2;
  out.set(oi, o);
  return out;
}

/** `challenge_digest = SHA-256(serialize(challenge))` (RFC 9577 section 2.2),
 * the 32-byte value a token carries and that feeds {@link blindToken}. */
export function tokenChallengeDigest(params: {
  issuerName: string;
  redemptionContext?: Uint8Array;
  originInfo?: Uint8Array;
}): Uint8Array {
  return sha256(serializeTokenChallenge(params));
}

/**
 * The Warren epoch-bound redemption context:
 * `SHA-256(context_label || epoch_be64)`. Frozen protocol derivation; the
 * issuer, verifier, and every SDK client MUST build the identical context for an
 * epoch or tokens will not verify.
 */
export function redemptionContextForEpoch(contextLabel: string, epoch: bigint): Uint8Array {
  const label = new TextEncoder().encode(contextLabel);
  const epochBe = new Uint8Array(8);
  new DataView(epochBe.buffer).setBigUint64(0, epoch, false);
  const msg = new Uint8Array(label.length + 8);
  msg.set(label, 0);
  msg.set(epochBe, label.length);
  return sha256(msg);
}

/** The epoch-bound Warren challenge digest: a named issuer, the epoch context,
 * no origin info. Convenience over {@link tokenChallengeDigest}. */
export function challengeDigestForEpoch(
  issuerName: string,
  contextLabel: string,
  epoch: bigint,
): Uint8Array {
  return tokenChallengeDigest({
    issuerName,
    redemptionContext: redemptionContextForEpoch(contextLabel, epoch),
  });
}

/** The `token_input` pre-image (RFC 9578): `token_type || nonce ||
 * challenge_digest || token_key_id` (98 bytes). */
function buildTokenInput(
  nonce: Uint8Array,
  challengeDigest: Uint8Array,
  tokenKeyId: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(2 + NONCE_LEN + CHALLENGE_DIGEST_LEN + TOKEN_KEY_ID_LEN);
  out[0] = (TOKEN_TYPE_BLIND_RSA >> 8) & 0xff;
  out[1] = TOKEN_TYPE_BLIND_RSA & 0xff;
  out.set(nonce, 2);
  out.set(challengeDigest, 2 + NONCE_LEN);
  out.set(tokenKeyId, 2 + NONCE_LEN + CHALLENGE_DIGEST_LEN);
  return out;
}

/** Secret client state bridging a blinded request and its finalization. Holds
 * the blinding secret; keep it only until the issuer's blind signature returns,
 * then consume it with {@link finalizeToken}. */
export interface TokenClientState {
  rInv: bigint;
  tokenInput: Uint8Array;
  nonce: Uint8Array;
  challengeDigest: Uint8Array;
  tokenKeyId: Uint8Array;
}

/**
 * Builds a blinded token request for `challengeDigest` against `pk` (RFC 9474
 * RSABSSA blind, deterministic variant). Returns the 256-byte blinded request
 * to POST to the issuer and the {@link TokenClientState} to finalize with.
 *
 * `nonce`/`blind` are injectable for deterministic test vectors ONLY; production
 * draws both from the CSPRNG (unlinkability depends on a fresh random blind).
 *
 * `random` replaces that CSPRNG with a caller-supplied byte source. The one use
 * is {@link deterministicTokenRandom}, which makes a batch re-derivable from
 * the wallet after a store loss; the draws below are made in a fixed order
 * (nonce, PSS salt, then the coprime search) because that order is part of what
 * a recovering client has to reproduce.
 */
export function blindToken(
  pk: IssuerPublicKey,
  challengeDigest: Uint8Array,
  opts?: { nonce?: Uint8Array; blind?: bigint; salt?: Uint8Array; random?: TokenRandom },
): { blindedRequest: Uint8Array; state: TokenClientState } {
  const draw = opts?.random ?? randomBytes;
  const nonce = opts?.nonce ?? draw(NONCE_LEN);
  const salt = opts?.salt ?? draw(HASH_LEN);
  const tokenInput = buildTokenInput(nonce, challengeDigest, pk.keyId);
  const em = emsaPssEncode(tokenInput, MOD_BITS - 1, salt);
  const m = os2ip(em);
  const r = opts?.blind ?? randomCoprime(pk.n, draw);
  const rInv = modInverse(r, pk.n);
  // blinded = m * r^e mod n
  const blinded = (m * modPow(r, pk.e, pk.n)) % pk.n;
  return {
    blindedRequest: i2osp(blinded, AUTHENTICATOR_LEN),
    state: { rInv, tokenInput, nonce, challengeDigest, tokenKeyId: pk.keyId },
  };
}

/**
 * Finalizes the issuer's blind signature into a verified {@link Token}
 * (unblinds, then verifies the resulting RSASSA-PSS signature against `pk` so a
 * bad blind signature is caught here, not at redemption).
 *
 * @throws {WarrenEdgeError} `token_issuer` if the blind signature is the wrong
 * size or the unblinded signature does not verify.
 */
export function finalizeToken(
  pk: IssuerPublicKey,
  blindSignature: Uint8Array,
  state: TokenClientState,
): Token {
  if (blindSignature.length !== AUTHENTICATOR_LEN) {
    throw new WarrenEdgeError('token_issuer', 'blind signature must be 256 bytes');
  }
  // s = blind_sig * r^-1 mod n
  const s = (os2ip(blindSignature) * state.rInv) % pk.n;
  const sig = i2osp(s, AUTHENTICATOR_LEN);
  // Verify the unblinded signature is a valid RSASSA-PSS signature over
  // token_input: recover EM = s^e mod n, then EMSA-PSS-VERIFY.
  const em = i2osp(modPow(s, pk.e, pk.n), AUTHENTICATOR_LEN);
  if (!emsaPssVerify(state.tokenInput, em, MOD_BITS - 1)) {
    throw new WarrenEdgeError('token_issuer', 'finalized token signature does not verify');
  }
  return new Token(state.nonce, state.challengeDigest, state.tokenKeyId, sig);
}

/** A finalized Privacy Pass token. Its {@link serialize} bytes are the 354-byte
 * `SessionToken` a Warren exit spends. */
export class Token {
  constructor(
    readonly nonce: Uint8Array,
    readonly challengeDigest: Uint8Array,
    readonly tokenKeyId: Uint8Array,
    readonly authenticator: Uint8Array,
  ) {}

  /** `nonce || challenge_digest || token_key_id || authenticator` (354 bytes),
   * the exact bytes an `IpRequestV7` carries as a session token. */
  serialize(): Uint8Array {
    const out = new Uint8Array(TOKEN_LEN);
    let o = 0;
    // token_input = token_type(2) || nonce || challenge_digest || token_key_id
    out[o++] = (TOKEN_TYPE_BLIND_RSA >> 8) & 0xff;
    out[o++] = TOKEN_TYPE_BLIND_RSA & 0xff;
    out.set(this.nonce, o);
    o += NONCE_LEN;
    out.set(this.challengeDigest, o);
    o += CHALLENGE_DIGEST_LEN;
    out.set(this.tokenKeyId, o);
    o += TOKEN_KEY_ID_LEN;
    out.set(this.authenticator, o);
    return out;
  }
}

/**
 * The redemption serial of a serialized token, `SHA-256(token_input)` (the
 * Rust `Token::serial`): the key an exit leases one live session per, fleet
 * wide. `undefined` when `bytes` is not a well-formed token (wrong length or
 * token type). A bearer-derived value: never log it.
 */
export function tokenSerial(bytes: Uint8Array): Uint8Array | undefined {
  if (bytes.length !== TOKEN_LEN) return undefined;
  if (((bytes[0] ?? 0) << 8) + (bytes[1] ?? 0) !== TOKEN_TYPE_BLIND_RSA) return undefined;
  return sha256(bytes.subarray(0, 2 + NONCE_LEN + CHALLENGE_DIGEST_LEN + TOKEN_KEY_ID_LEN));
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function randomCoprime(n: bigint, draw: TokenRandom): bigint {
  for (;;) {
    const r = os2ip(draw(AUTHENTICATOR_LEN)) % n;
    if (r > 1n) {
      try {
        modInverse(r, n);
        return r;
      } catch {
        // not coprime, retry
      }
    }
  }
}
