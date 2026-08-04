/**
 * RFC 9180 HPKE, base mode, suite
 * `DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305`, restricted to
 * exactly what the Warren multi-hop seal needs: sender KEM setup (Encap) and the
 * secret-export interface (`Context.Export`). Warren does NOT use HPKE's
 * sequential `Seal`; it exports a fresh per-packet key and runs
 * ChaCha20-Poly1305 itself (see `./seal.ts`), so only Encap + the exporter
 * secret are reproduced here.
 *
 * Byte-for-byte equivalent to the Rust `hpke` crate as used by
 * `warrenguard-multihop`, which is the wire contract a Warren exit decrypts
 * against.
 */

import { x25519 } from '@noble/curves/ed25519';
import { expand, extract } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

const KEM_ID = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const KDF_ID = 0x0001; // HKDF-SHA256
const AEAD_ID = 0x0003; // ChaCha20Poly1305
const NSECRET = 32; // KEM shared-secret length
const NH = 32; // HKDF-SHA256 output length

const HPKE_V1 = new TextEncoder().encode('HPKE-v1');

function i2osp2(n: number): Uint8Array {
  return Uint8Array.from([(n >> 8) & 0xff, n & 0xff]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const KEM_SUITE_ID = concat(new TextEncoder().encode('KEM'), i2osp2(KEM_ID));
const HPKE_SUITE_ID = concat(
  new TextEncoder().encode('HPKE'),
  i2osp2(KEM_ID),
  i2osp2(KDF_ID),
  i2osp2(AEAD_ID),
);

function labeledExtract(
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array,
  suiteId: Uint8Array,
): Uint8Array {
  const labeledIkm = concat(HPKE_V1, suiteId, new TextEncoder().encode(label), ikm);
  return extract(sha256, labeledIkm, salt);
}

function labeledExpand(
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
  suiteId: Uint8Array,
): Uint8Array {
  const labeledInfo = concat(
    i2osp2(length),
    HPKE_V1,
    suiteId,
    new TextEncoder().encode(label),
    info,
  );
  return expand(sha256, prk, labeledInfo, length);
}

/** A configured HPKE sender: the encapsulated key to put on the wire and the
 * exporter secret the per-packet key is derived from. */
export interface HpkeSender {
  /** 32-byte ephemeral X25519 public key (the wire `encapsulated_key`). */
  enc: Uint8Array;
  /** The RFC 9180 exporter secret (Nh bytes); input to {@link exportSecret}. */
  exporterSecret: Uint8Array;
}

/**
 * DHKEM(X25519) Encap against `pkR`, then the base-mode key schedule with
 * `info`, returning the wire `enc` and the exporter secret.
 *
 * `ephemeralPriv` (32 bytes) is injectable ONLY so tests can freeze a golden
 * vector; production callers omit it and a fresh CSPRNG ephemeral is used
 * (X25519 forward secrecy depends on it being random and single-use).
 */
export function setupBaseSender(
  pkR: Uint8Array,
  info: Uint8Array,
  ephemeralPriv?: Uint8Array,
): HpkeSender {
  const skE = ephemeralPriv ?? x25519.utils.randomPrivateKey();
  const pkE = x25519.getPublicKey(skE);
  const dh = x25519.getSharedSecret(skE, pkR);

  // DHKEM ExtractAndExpand.
  const kemContext = concat(pkE, pkR);
  const eaePrk = labeledExtract(new Uint8Array(0), 'eae_prk', dh, KEM_SUITE_ID);
  const sharedSecret = labeledExpand(eaePrk, 'shared_secret', kemContext, NSECRET, KEM_SUITE_ID);

  // KeyScheduleS, mode_base (0x00), empty PSK.
  const empty = new Uint8Array(0);
  const pskIdHash = labeledExtract(empty, 'psk_id_hash', empty, HPKE_SUITE_ID);
  const infoHash = labeledExtract(empty, 'info_hash', info, HPKE_SUITE_ID);
  const keyScheduleContext = concat(Uint8Array.from([0x00]), pskIdHash, infoHash);
  const secret = labeledExtract(sharedSecret, 'secret', empty, HPKE_SUITE_ID);
  const exporterSecret = labeledExpand(secret, 'exp', keyScheduleContext, NH, HPKE_SUITE_ID);

  return { enc: pkE, exporterSecret };
}

/**
 * RFC 9180 `Context.Export`: derive `length` bytes of secret keying material
 * for `exporterContext` from `exporterSecret`.
 */
export function exportSecret(
  exporterSecret: Uint8Array,
  exporterContext: Uint8Array,
  length: number,
): Uint8Array {
  return labeledExpand(exporterSecret, 'sec', exporterContext, length, HPKE_SUITE_ID);
}
